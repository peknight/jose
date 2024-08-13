package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.jose.error.jws.{InvalidHmacSHAKeyLength, JsonWebSignatureError}
import com.peknight.jose.jwa.signature.HmacSHAAlgorithm
import com.peknight.security.mac.MAC
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

object HmacSHAOps extends SignatureOps[HmacSHAAlgorithm, Key, Key]:
  def typedSign[F[_] : Sync](algorithm: HmacSHAAlgorithm, key: Key, data: ByteVector, useLegacyName: Boolean = false,
                             provider: Option[Provider | JProvider] = None, random: Option[SecureRandom] = None)
  : F[Either[JsonWebSignatureError, ByteVector]] =
    MAC.mac[F](algorithm.mac, key, data, provider).map(_.asRight)

  def typedVerify[F[_] : Sync](algorithm: HmacSHAAlgorithm, key: Key, data: ByteVector, signed: ByteVector,
                               useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    given CanEqual[ByteVector, ByteVector] = CanEqual.derived
    MAC.mac[F](algorithm.mac, key, data, provider).map(sig => (sig == signed).asRight)

  def typedValidateSigningKey(algorithm: HmacSHAAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    validateKey(algorithm, key)

  def typedValidateVerificationKey(algorithm: HmacSHAAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    validateKey(algorithm, key)

  def validateKey(algorithm: HmacSHAAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    Option(key.getEncoded).map(_.length * 8) match
      case Some(bitLength) =>
        val minimumKeyLength = algorithm.mac.digest.bitLength
        if bitLength < minimumKeyLength then
          Left(InvalidHmacSHAKeyLength(algorithm, bitLength, minimumKeyLength))
        else Right(())
      case _ => Right(())
end HmacSHAOps
