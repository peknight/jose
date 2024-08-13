package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.error.jws.JsonWebSignatureError
import com.peknight.jose.jwa.signature.`RSASSA-PSSAlgorithm`
import com.peknight.security.Security
import com.peknight.security.provider.Provider
import com.peknight.security.signature.{Signature, `RSASSA-PSS`}
import scodec.bits.ByteVector

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

object `RSASSA-PSSOps` extends RSASSAOps[`RSASSA-PSSAlgorithm`]:

  def typedSign[F[_] : Sync](algorithm: `RSASSA-PSSAlgorithm`, key: RSAPrivateKey, data: ByteVector,
                             useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                             random: Option[SecureRandom] = None): F[Either[JsonWebSignatureError, ByteVector]] =
    for
      algorithms <- Security.getAlgorithms[F](Signature)
      (algo, params) =
        if algorithms.contains(`RSASSA-PSS`.algorithm) && useLegacyName then
          (`RSASSA-PSS`, Some(algorithm.toPSSParameterSpec))
        else (algorithm.signature, None)
      signed <- Signature.sign[F](algo, key, data, provider, params, random)
    yield signed.asRight

  def typedVerify[F[_] : Sync](algorithm: `RSASSA-PSSAlgorithm`, key: RSAPublicKey, data: ByteVector, signed: ByteVector,
                               useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    for
      algorithms <- Security.getAlgorithms[F](Signature)
      (algo, params) =
        if algorithms.contains(`RSASSA-PSS`.algorithm) && useLegacyName then
          (`RSASSA-PSS`, Some(algorithm.toPSSParameterSpec))
        else (algorithm.signature, None)
      flag <- Signature.publicKeyVerify[F](algo, key, data, signed, provider, params)
    yield flag.asRight
end `RSASSA-PSSOps`
