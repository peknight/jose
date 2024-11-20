package com.peknight.jose.jwk

import cats.Id
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.security.cipher.AES

import javax.crypto.spec.SecretKeySpec as JSecretKeySpec

trait OctetSequenceJsonWebKeyPlatform { self: OctetSequenceJsonWebKey =>
  def toKey: Either[DecodingFailure, JSecretKeySpec] = self.keyValue.decode[Id].map(AES.secretKeySpec)
}
