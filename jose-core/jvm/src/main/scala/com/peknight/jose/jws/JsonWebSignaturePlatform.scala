package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.base64UrlEncodePayloadLabel
import com.peknight.jose.jwx.JoseConfiguration
import com.peknight.security.error.InvalidSignature
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue

import java.security.{Key, Provider as JProvider}

trait JsonWebSignaturePlatform { self: JsonWebSignature =>
  def verify[F[_]: Sync](key: Option[Key] = None, configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, Boolean]] =
    val either =
      for
        h <- self.getUnprotectedHeader
        p <- self.getProtectedHeader
        data <- JsonWebSignature.toBytes(p, self.payload, configuration.charset)
        signed <- self.signature.decode[Id]
        _ <- h.checkCritical(base64UrlEncodePayloadLabel :: configuration.knownCriticalHeaders)
      yield
        JsonWebSignature.handleVerify[F](h.algorithm, key, data, signed, configuration)
    either.fold(_.asLeft.pure, identity)

  def check[F[_]: Sync](key: Option[Key] = None, configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(verify[F](key, configuration))
}
