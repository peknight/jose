package com.peknight.jose.jws

import cats.data.NonEmptyList
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.parallel.*
import cats.syntax.traverse.*
import cats.{Id, Parallel}
import com.peknight.error.Error
import com.peknight.jose.error.MissingVerifyPrimitive
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.error.InvalidSignature
import com.peknight.validation.std.either.isTrue

trait JsonWebSignaturesPlatform { self: JsonWebSignatures =>
  def parVerify[F[_]: Sync: Parallel](f: JoseHeader => Option[VerifyPrimitive]): F[Either[Error, Boolean]] =
    handleVerify(f)(_.parSequence)

  def verify[F[_]: Sync](f: JoseHeader => Option[VerifyPrimitive]): F[Either[Error, Boolean]] =
    handleVerify(f)(_.sequence)

  def parCheck[F[_]: Sync: Parallel](f: JoseHeader => Option[VerifyPrimitive]): F[Either[Error, Unit]] =
    parVerify[F](f).map(_.flatMap(isTrue(_, InvalidSignature)))

  def check[F[_]: Sync](f: JoseHeader => Option[VerifyPrimitive]): F[Either[Error, Unit]] =
    verify[F](f).map(_.flatMap(isTrue(_, InvalidSignature)))

  def handleVerify[F[_]: Sync](f: JoseHeader => Option[VerifyPrimitive])
                              (sequence: NonEmptyList[F[Either[Error, Boolean]]] => F[NonEmptyList[Either[Error, Boolean]]])
  : F[Either[Error, Boolean]] =
    sequence(self.signatures.map { signature =>
      val either =
        for
          h <- signature.getUnprotectedHeader
          primitive <- f(h).toRight(MissingVerifyPrimitive(h))
          p <- signature.getProtectedHeader
          data <- JsonWebSignature.toBytes(p, self.payload)
          signed <- signature.signature.decode[Id]
        yield
          JsonWebSignature.handleVerify[F](h.algorithm, primitive.key, data, signed, primitive.doKeyValidation,
            primitive.useLegacyName, primitive.provider)
      either.fold(_.asLeft.pure, identity)
    }).map(_.sequence.map(_.forall(identity)))
}

