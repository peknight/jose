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
import com.peknight.jose.jwx.{JoseConfiguration, JosePrimitive}
import com.peknight.jose.syntax.x509Certificate.base64UrlThumbprint
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-1`, `SHA-256`}
import com.peknight.validation.collection.list.either.nonEmpty

import java.security.Key
import java.security.cert.X509Certificate

case class VerificationPrimitive(key: Option[Key] = None, configuration: JoseConfiguration = JoseConfiguration.default)
  extends JosePrimitive
object VerificationPrimitive:
  def handleNoneAlgorithm[F[_]: Applicative, A](jws: JsonWebSignature,
                                                configuration: JoseConfiguration = JoseConfiguration.default)
                                               (noneF: JoseConfiguration => A)
                                               (verificationPrimitivesF: => F[Either[Error, A]])
  : F[Either[Error, A]] =
    jws.getUnprotectedHeader match
      case Left(error) => error.asLeft[A].pure[F]
      case Right(header) if header.isNoneAlgorithm => noneF(configuration).asRight[Error].pure[F]
      case _ => verificationPrimitivesF

  def handleVerificationPrimitivesF[F[_]: Applicative](jws: JsonWebSignature,
                                                       configuration: JoseConfiguration = JoseConfiguration.default)
                                                      (verificationPrimitivesF: => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
  : F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    handleNoneAlgorithm[F, NonEmptyList[VerificationPrimitive]](jws, configuration)(configuration =>
      NonEmptyList.one(VerificationPrimitive(None, configuration))
    )(verificationPrimitivesF)

  def handleFilterForVerification[F[_]: Applicative](jws: JsonWebSignature,
                                                     configuration: JoseConfiguration = JoseConfiguration.default)
                                                    (filterF: => F[Either[Error, List[JsonWebKey]]])
  : F[Either[Error, List[JsonWebKey]]] =
    handleNoneAlgorithm[F, List[JsonWebKey]](jws, configuration)(configuration => Nil)(filterF)

  def verificationKey[F[_]: Applicative](key: Option[Key] = None)
  : (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    (jws, configuration) => handleVerificationPrimitivesF[F](jws, configuration)(
      NonEmptyList.one(VerificationPrimitive(key, configuration)).asRight[Error].pure[F]
    )

  def defaultVerificationPrimitivesF[F[_]: Applicative]
  : (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    (jws, configuration) => handleVerificationPrimitivesF[F](jws, configuration)(empty)

  def x509Certificates[F[_]: Sync](certificates: List[X509Certificate], tryAllOnNoThumbHeader: Boolean = false)
  : (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    (jws, configuration) => handleVerificationPrimitivesF[F](jws, configuration)(
      jws.getUnprotectedHeader match
        case Left(error) => error.asLeft[NonEmptyList[VerificationPrimitive]].pure[F]
        case Right(header) => (header.x509CertificateSHA1Thumbprint, header.x509CertificateSHA256Thumbprint) match
          case (None, None) if tryAllOnNoThumbHeader =>
            nonEmpty(certificates.map(certificate => toVerificationPrimitive(certificate, configuration))).pure[F]
          case (None, None) => empty
          case (x5t, x5tS256) => Monad[[X] =>> EitherT[F, Error, X]]
            .tailRecM[List[X509Certificate], NonEmptyList[VerificationPrimitive]](certificates) {
              case head :: tail => (x5t, x5tS256) match
                case (Some(x5t), _) => handleX509Certificate[F](head, tail, `SHA-1`, x5t, configuration)
                case (_, Some(x5tS256)) => handleX509Certificate[F](head, tail, `SHA-256`, x5tS256, configuration)
                case _ => EitherT(empty)
              case Nil => EitherT(empty)
            }.value
    )

  private def empty[F[_]: Applicative, A]: F[Either[Error, A]] =
    CollectionEmpty.label("primitives").asLeft[A].pure[F]

  private def handleX509Certificate[F[_]: Sync](head: X509Certificate, tail: List[X509Certificate],
                                                hashAlg: MessageDigestAlgorithm, expected: Base64UrlNoPad,
                                                configuration: JoseConfiguration)
  : EitherT[F, Error, Either[List[X509Certificate], NonEmptyList[VerificationPrimitive]]] =
    EitherT(head.base64UrlThumbprint[F](hashAlg, configuration.messageDigestProvider)).map { thumb =>
      if thumb === expected then
        NonEmptyList.one(toVerificationPrimitive(head, configuration)).asRight[List[X509Certificate]]
      else
        tail.asLeft[NonEmptyList[VerificationPrimitive]]
    }

  private def toVerificationPrimitive(x509Certificate: X509Certificate, configuration: JoseConfiguration)
  : VerificationPrimitive =
    VerificationPrimitive(Some(x509Certificate.getPublicKey), configuration)

end VerificationPrimitive
