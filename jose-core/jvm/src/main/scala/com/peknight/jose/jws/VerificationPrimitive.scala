package com.peknight.jose.jws

import cats.Applicative
import cats.data.NonEmptyList
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.error.collection.CollectionEmpty
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwx.{JoseConfiguration, JosePrimitive}

import java.security.Key

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
    (jws, configuration) => handleVerificationPrimitivesF[F](jws, configuration)(
      CollectionEmpty.label("primitives").asLeft[NonEmptyList[VerificationPrimitive]].pure[F]
    )
end VerificationPrimitive
