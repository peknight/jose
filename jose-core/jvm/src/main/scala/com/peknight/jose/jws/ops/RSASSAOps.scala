package com.peknight.jose.jws.ops

import com.peknight.jose.error.jws.{InvalidRSAKeyLength, JsonWebSignatureError}
import com.peknight.jose.jwa.signature.RSASSAAlgorithm

import java.security.Key
import java.security.interfaces.{RSAKey, RSAPrivateKey, RSAPublicKey}
import scala.reflect.ClassTag

trait RSASSAOps[Algorithm <: RSASSAAlgorithm : ClassTag] extends SignatureOps[Algorithm, RSAPrivateKey, RSAPublicKey]:
  def typedValidateSigningKey(algorithm: Algorithm, key: RSAPrivateKey): Either[JsonWebSignatureError, Unit] =
    validateKey(key)

  def typedValidateVerificationKey(algorithm: Algorithm, key: RSAPublicKey): Either[JsonWebSignatureError, Unit] =
    validateKey(key)

  def validateKey(key: Key): Either[JsonWebSignatureError, Unit] =
    key match
      case k: RSAKey =>
        val minimumLength = 2048
        Option(k.getModulus).flatMap(modulus => Option(modulus.bitLength())) match
          case Some(bitLength) if bitLength < minimumLength => Left(InvalidRSAKeyLength(bitLength, minimumLength))
          case _ => Right(())
      case _ => Right(())
end RSASSAOps
