package com.peknight.jose.jwa.signature

import com.peknight.error.Error
import com.peknight.jose.jwa.checkRSAKeySize
import com.peknight.validation.std.either.typed

import java.security.Key
import java.security.interfaces.{RSAKey, RSAPrivateKey, RSAPublicKey}

trait RSASSAPlatform extends SignaturePlatform { self: JWSAlgorithm =>
  def validateSigningKey(key: Key): Either[Error, Unit] =
    typed[RSAPrivateKey](key).flatMap(validateKey)

  def validateVerificationKey(key: Key): Either[Error, Unit] =
    typed[RSAPublicKey](key).flatMap(validateKey)

  def validateKey(key: RSAKey): Either[Error, Unit] = checkRSAKeySize(key)
}
