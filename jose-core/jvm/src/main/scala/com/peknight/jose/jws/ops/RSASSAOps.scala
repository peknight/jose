package com.peknight.jose.jws.ops

import com.peknight.jose.error.jws.{InvalidRSAKeyLength, JsonWebSignatureError}

import java.security.Key
import java.security.interfaces.RSAKey

trait RSASSAOps:
  def validateKey(key: Key): Either[JsonWebSignatureError, Unit] =
    key match
      case k: RSAKey =>
        val minimumLength = 2048
        Option(k.getModulus).flatMap(modulus => Option(modulus.bitLength())) match
          case Some(bitLength) if bitLength < minimumLength => Left(InvalidRSAKeyLength(bitLength, minimumLength))
          case _ => Right(())
      case _ => Right(())
end RSASSAOps
