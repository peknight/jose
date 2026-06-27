package com.peknight.jose.jwk

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.error.Error
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.security.cipher.AES
import com.peknight.security.provider.Provider

import java.security.{Key, Provider as JProvider}
import javax.crypto.spec.SecretKeySpec as JSecretKeySpec

trait OctetSequenceJsonWebKeyPlatform { self: OctetSequenceJsonWebKey =>
  def toKey: Either[DecodingFailure, JSecretKeySpec] = self.keyValue.decode[Id].map(AES.secretKeySpec)
  def toKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Key]] = toKey.pure
}
