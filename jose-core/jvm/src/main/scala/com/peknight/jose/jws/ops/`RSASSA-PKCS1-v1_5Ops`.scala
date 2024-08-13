package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.jose.error.jws.JsonWebSignatureError
import com.peknight.jose.jwa.signature.`RSASSA-PKCS1-v1_5Algorithm`
import com.peknight.security.provider.Provider
import com.peknight.security.signature.Signature
import scodec.bits.ByteVector

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

object `RSASSA-PKCS1-v1_5Ops` extends RSASSAOps[`RSASSA-PKCS1-v1_5Algorithm`]:
  def typedSign[F[_] : Sync](algorithm: `RSASSA-PKCS1-v1_5Algorithm`, key: RSAPrivateKey, data: ByteVector,
                             useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                             random: Option[SecureRandom] = None): F[Either[JsonWebSignatureError, ByteVector]] =
    Signature.sign[F](algorithm.signature, key, data, provider = provider, random = random).map(_.asRight)

  def typedVerify[F[_] : Sync](algorithm: `RSASSA-PKCS1-v1_5Algorithm`, key: RSAPublicKey, data: ByteVector,
                               signed: ByteVector, useLegacyName: Boolean = false,
                               provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    Signature.publicKeyVerify[F](algorithm.signature, key, data, signed, provider = provider).map(_.asRight)
end `RSASSA-PKCS1-v1_5Ops`
