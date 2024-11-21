package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.base64UrlEncodePayloadLabel
import com.peknight.security.error.InvalidSignature
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue

import java.security.{Key, Provider as JProvider}

trait JsonWebSignaturePlatform { self: JsonWebSignature =>
  def verify[F[_]: Sync](key: Option[Key] = None, knownCriticalHeaders: List[String] = List.empty[String],
                         doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                         provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    val either =
      for
        h <- self.getUnprotectedHeader
        p <- self.getProtectedHeader
        data <- JsonWebSignature.toBytes(p, self.payload)
        signed <- self.signature.decode[Id]
        _ <- h.checkCritical(base64UrlEncodePayloadLabel :: knownCriticalHeaders)
      yield
        JsonWebSignature.handleVerify[F](h.algorithm, key, data, signed, doKeyValidation, useLegacyName, provider)
    either.fold(_.asLeft.pure, identity)

  def check[F[_]: Sync](key: Option[Key] = None, knownCriticalHeaders: List[String] = List.empty[String],
                        doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                        provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]] =
    verify[F](key, knownCriticalHeaders, doKeyValidation, useLegacyName, provider)
      .map(_.flatMap(isTrue(_, InvalidSignature)))
}
