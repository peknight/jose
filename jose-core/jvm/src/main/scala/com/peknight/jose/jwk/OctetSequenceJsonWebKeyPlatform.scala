package com.peknight.jose.jwk

import cats.Applicative
import cats.syntax.functor.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.security.cipher.AES
import com.peknight.security.crypto.spec.SecretKeySpec

import javax.crypto.spec.SecretKeySpec as JSecretKeySpec

trait OctetSequenceJsonWebKeyPlatform { self: OctetSequenceJsonWebKey =>
  def toKey[F[_]: Applicative]: F[Either[DecodingFailure, JSecretKeySpec]] =
    self.keyValue.decode[F].map(_.map(SecretKeySpec(_, AES)))
}
