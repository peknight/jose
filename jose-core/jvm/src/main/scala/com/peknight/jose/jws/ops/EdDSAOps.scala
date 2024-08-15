package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.jose.error.jws.JsonWebSignatureError
import com.peknight.jose.jwa.signature.EdDSA
import com.peknight.security.provider.Provider
import com.peknight.security.signature.Signature
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPrivateKey, EdECPublicKey}
import java.security.{SecureRandom, Provider as JProvider}

object EdDSAOps extends SignatureOps[EdDSA, EdECPrivateKey, EdECPublicKey]:
  def typedSign[F[_] : Sync](algorithm: EdDSA, key: EdECPrivateKey, data: ByteVector, useLegacyName: Boolean = false,
                             provider: Option[Provider | JProvider] = None, random: Option[SecureRandom] = None)
  : F[Either[JsonWebSignatureError, ByteVector]] =
    Signature.sign[F](algorithm, key, data, provider = provider, random = random).map(_.asRight)

  def typedVerify[F[_] : Sync](algorithm: EdDSA, key: EdECPublicKey, data: ByteVector, signed: ByteVector,
                               useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    Signature.publicKeyVerify[F](algorithm, key, data, signed, provider = provider).map(_.asRight)

  def typedValidateSigningKey(algorithm: EdDSA, key: EdECPrivateKey): Either[JsonWebSignatureError, Unit] = ().asRight

  def typedValidateVerificationKey(algorithm: EdDSA, key: EdECPublicKey): Either[JsonWebSignatureError, Unit] = ().asRight
end EdDSAOps
