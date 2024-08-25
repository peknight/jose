package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.security.provider.Provider

import java.security.{Key, Provider as JProvider}

trait JsonWebSignaturePlatform { self: JsonWebSignature =>
  def verify[F[_]: Sync](key: Option[Key] = None, doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                         provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]] =
    val either =
      for
        h <- self.getUnprotectedHeader
        p <- self.getProtectedHeader
        data <- JsonWebSignature.toBytes(p, self.payload)
        signed <- self.signature.decode[Id]
      yield
        JsonWebSignature.handleVerify[F](h.algorithm, key, data, signed, doKeyValidation, useLegacyName, provider)
    either.fold(_.asLeft.pure, identity)
}
