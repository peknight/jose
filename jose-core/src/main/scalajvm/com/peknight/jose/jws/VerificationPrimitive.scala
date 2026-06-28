package com.peknight.jose.jws

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.eq.*
import cats.{Applicative, Monad}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.collection.CollectionEmpty
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwx.{JoseConfig, JosePrimitive}
import com.peknight.jose.syntax.x509Certificate.base64UrlThumbprint
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-1`, `SHA-256`}
import com.peknight.validation.collection.list.either.nonEmpty

import java.security.Key
import java.security.cert.X509Certificate

case class VerificationPrimitive(key: Option[Key] = None, config: JoseConfig = JoseConfig.default)
  extends JosePrimitive
object VerificationPrimitive:
  def handleNoneAlgorithm[F[_]: Applicative, A](jws: JsonWebSignature,
                                                config: JoseConfig = JoseConfig.default)
                                               (noneF: JoseConfig => A)
                                               (verificationPrimitivesF: => F[Either[Error, A]])
  : F[Either[Error, A]] =
    jws.getUnprotectedHeader match
      case Left(error) => error.asLeft[A].pure[F]
      case Right(header) if header.isNoneAlgorithm => noneF(config).asRight[Error].pure[F]
      case _ => verificationPrimitivesF

  def handleVerificationPrimitivesF[F[_]: Applicative](jws: JsonWebSignature,
                                                       config: JoseConfig = JoseConfig.default)
                                                      (verificationPrimitivesF: => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
  : F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    handleNoneAlgorithm[F, NonEmptyList[VerificationPrimitive]](jws, config)(config =>
      NonEmptyList.one(VerificationPrimitive(None, config))
    )(verificationPrimitivesF)

  def handleFilterForVerification[F[_]: Applicative](jws: JsonWebSignature,
                                                     config: JoseConfig = JoseConfig.default)
                                                    (filterF: => F[Either[Error, List[JsonWebKey]]])
  : F[Either[Error, List[JsonWebKey]]] =
    handleNoneAlgorithm[F, List[JsonWebKey]](jws, config)(config => Nil)(filterF)

  def verificationKey[F[_]: Applicative](key: Option[Key] = None)
  : (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    (jws, config) => handleVerificationPrimitivesF[F](jws, config)(
      NonEmptyList.one(VerificationPrimitive(key, config)).asRight[Error].pure[F]
    )

  def defaultVerificationPrimitivesF[F[_]: Applicative]
  : (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    (jws, config) => handleVerificationPrimitivesF[F](jws, config)(empty)

  def x509Certificates[F[_]: Sync](certificates: List[X509Certificate], tryAllOnNoThumbHeader: Boolean = false)
  : (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    (jws, config) => handleVerificationPrimitivesF[F](jws, config)(
      jws.getUnprotectedHeader match
        case Left(error) => error.asLeft[NonEmptyList[VerificationPrimitive]].pure[F]
        case Right(header) => (header.x509CertificateSHA1Thumbprint, header.x509CertificateSHA256Thumbprint) match
          case (None, None) if tryAllOnNoThumbHeader =>
            nonEmpty(certificates.map(certificate => toVerificationPrimitive(certificate, config))).pure[F]
          case (None, None) => empty
          case (x5t, x5tS256) => Monad[[X] =>> EitherT[F, Error, X]]
            .tailRecM[List[X509Certificate], NonEmptyList[VerificationPrimitive]](certificates) {
              case head :: tail => (x5t, x5tS256) match
                case (Some(x5t), _) => handleX509Certificate[F](head, tail, `SHA-1`, x5t, config)
                case (_, Some(x5tS256)) => handleX509Certificate[F](head, tail, `SHA-256`, x5tS256, config)
                case _ => EitherT(empty)
              case Nil => EitherT(empty)
            }.value
    )

  private def empty[F[_]: Applicative, A]: F[Either[Error, A]] =
    CollectionEmpty.label("primitives").asLeft[A].pure[F]

  private def handleX509Certificate[F[_]: Sync](head: X509Certificate, tail: List[X509Certificate],
                                                hashAlg: MessageDigestAlgorithm, expected: Base64UrlNoPad,
                                                config: JoseConfig)
  : EitherT[F, Error, Either[List[X509Certificate], NonEmptyList[VerificationPrimitive]]] =
    EitherT(head.base64UrlThumbprint[F](hashAlg, config.messageDigestProvider)).map { thumb =>
      if thumb === expected then
        NonEmptyList.one(toVerificationPrimitive(head, config)).asRight[List[X509Certificate]]
      else
        tail.asLeft[NonEmptyList[VerificationPrimitive]]
    }

  private def toVerificationPrimitive(x509Certificate: X509Certificate, config: JoseConfig)
  : VerificationPrimitive =
    VerificationPrimitive(Some(x509Certificate.getPublicKey), config)

end VerificationPrimitive
