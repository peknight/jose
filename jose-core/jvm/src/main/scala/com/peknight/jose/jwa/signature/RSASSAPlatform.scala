package com.peknight.jose.jwa.signature

import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.validation.spire.math.interval.either.atOrAbove
import com.peknight.validation.std.either.typed

import java.security.Key
import java.security.interfaces.{RSAKey, RSAPrivateKey, RSAPublicKey}

trait RSASSAPlatform extends SignaturePlatform { self: JWSAlgorithm =>
  def validateSigningKey(key: Key): Either[Error, Unit] =
    typed[RSAPrivateKey](key).flatMap(validateKey)

  def validateVerificationKey(key: Key): Either[Error, Unit] =
    typed[RSAPublicKey](key).flatMap(validateKey)

  def validateKey(key: RSAKey): Either[Error, Unit] =
    Option(key.getModulus)
      .flatMap(modulus => Option(modulus.bitLength()))
      .toRight(OptionEmpty.label("modulusBitLength"))
      .flatMap(bitLength => atOrAbove(bitLength, 2048).label("bitLength").as(()))
}
