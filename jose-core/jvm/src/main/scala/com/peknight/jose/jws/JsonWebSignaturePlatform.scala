package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.functor.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.security.provider.Provider

import java.security.{Key, Provider as JProvider}

trait JsonWebSignaturePlatform { self: JsonWebSignature =>
  def verify[F[_]: Sync](key: Option[Key], doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                         provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, Boolean]] =
    val eitherT =
      for
        h <- EitherT(self.getUnprotectedHeader.pure[F])
        p <- EitherT(self.getProtectedHeader.left.map(DecodingFailure.apply).pure[F])
        data <- EitherT(JsonWebSignature.toBytes(p, self.payload).left.map(DecodingFailure.apply).pure[F])
        signed <- EitherT(self.signature.decode[Id].pure[F])
        flag <- EitherT(JsonWebSignature.handleVerify[F](h.algorithm, key, data, signed, doKeyValidation, useLegacyName,
          provider).map(_.left.map(DecodingFailure.apply)))
      yield
        flag
    eitherT.value
}
