package com.peknight.jose.jws

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.parallel.*
import cats.syntax.traverse.*
import cats.{Id, Parallel}
import com.peknight.error.Error
import com.peknight.jose.error.MissingVerifyPrimitive
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader}
import com.peknight.security.error.InvalidSignature
import com.peknight.validation.std.either.isTrue

trait JsonWebSignaturesPlatform { self: JsonWebSignatures =>
  def parVerify[F[_]: Sync: Parallel](configuration: JoseConfiguration = JoseConfiguration.default)
                                     (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
  : F[Either[Error, Boolean]] =
    handleVerify(configuration)(verificationPrimitiveF)(_.parSequence)

  def verify[F[_]: Sync](configuration: JoseConfiguration = JoseConfiguration.default)
                        (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
  : F[Either[Error, Boolean]] =
    handleVerify(configuration)(verificationPrimitiveF)(_.sequence)

  def parCheck[F[_]: Sync: Parallel](configuration: JoseConfiguration = JoseConfiguration.default)
                                    (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(parVerify[F](configuration)(verificationPrimitiveF))

  def check[F[_]: Sync](configuration: JoseConfiguration = JoseConfiguration.default)
                       (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(verify[F](configuration)(verificationPrimitiveF))

  private def handleVerify[F[_]: Sync](configuration: JoseConfiguration = JoseConfiguration.default)
                                      (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                      (sequence: NonEmptyList[F[Either[Error, Boolean]]] => F[NonEmptyList[Either[Error, Boolean]]])
  : F[Either[Error, Boolean]] =
    sequence(self.toList.map { signature =>
      val eitherT =
        for
          primitive <- EitherT(verificationPrimitiveF(signature, configuration))
          res <- EitherT(signature.verify[F](primitive.key, primitive.configuration))
        yield
          res
      eitherT.value
    }).map(_.sequence.map(_.forall(identity)))
}

