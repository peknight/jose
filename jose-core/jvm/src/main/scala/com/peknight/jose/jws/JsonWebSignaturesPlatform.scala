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
import com.peknight.jose.jwx.{JoseContext, JoseHeader}
import com.peknight.security.error.InvalidSignature
import com.peknight.validation.std.either.isTrue

trait JsonWebSignaturesPlatform { self: JsonWebSignatures =>
  def parVerify[F[_]: Sync: Parallel](context: JoseContext = JoseContext.default)
                                     (f: (JsonWebSignature, JoseContext) => F[Either[Error, VerifyPrimitive]])
  : F[Either[Error, Boolean]] =
    handleVerify(context)(f)(_.parSequence)

  def verify[F[_]: Sync](context: JoseContext = JoseContext.default)
                        (f: (JsonWebSignature, JoseContext) => F[Either[Error, VerifyPrimitive]])
  : F[Either[Error, Boolean]] =
    handleVerify(context)(f)(_.sequence)

  def parCheck[F[_]: Sync: Parallel](context: JoseContext = JoseContext.default)
                                    (f: (JsonWebSignature, JoseContext) => F[Either[Error, VerifyPrimitive]])
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(parVerify[F](context)(f))

  def check[F[_]: Sync](context: JoseContext = JoseContext.default)
                       (f: (JsonWebSignature, JoseContext) => F[Either[Error, VerifyPrimitive]])
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(verify[F](context)(f))

  private def handleVerify[F[_]: Sync](context: JoseContext = JoseContext.default)
                                      (f: (JsonWebSignature, JoseContext) => F[Either[Error, VerifyPrimitive]])
                                      (sequence: NonEmptyList[F[Either[Error, Boolean]]] => F[NonEmptyList[Either[Error, Boolean]]])
  : F[Either[Error, Boolean]] =
    sequence(self.toList.map { signature =>
      val eitherT =
        for
          primitive <- EitherT(f(signature, context))
          res <- EitherT(signature.verify[F](primitive.key, primitive.context))
        yield
          res
      eitherT.value
    }).map(_.sequence.map(_.forall(identity)))
}

