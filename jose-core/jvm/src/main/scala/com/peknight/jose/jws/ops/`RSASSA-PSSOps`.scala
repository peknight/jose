package com.peknight.jose.jws.ops

import cats.effect.kernel.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.jwa.signature.{RSASSAAlgorithm, `RSASSA-PSSAlgorithm`}
import com.peknight.security.Security
import com.peknight.security.provider.Provider
import com.peknight.security.signature.{Signature, SignatureAlgorithm, `RSASSA-PSS`}
import scodec.bits.ByteVector

import java.security.{PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

object `RSASSA-PSSOps` extends RSASSAOps:
  def sign[F[_] : Sync](algorithm: `RSASSA-PSSAlgorithm`, key: PrivateKey, data: ByteVector,
                        useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                        random: Option[SecureRandom] = None): F[ByteVector] =
    for
      algorithms <- Security.getAlgorithms[F](Signature)
      (algo, params) =
        if algorithms.contains(`RSASSA-PSS`.algorithm) && useLegacyName then
          (`RSASSA-PSS`, Some(algorithm.toPSSParameterSpec))
        else (algorithm.signature, None)
      signed <- Signature.sign[F](algo, key, data, provider, params, random)
    yield signed

  def verify[F[_] : Sync](algorithm: `RSASSA-PSSAlgorithm`, key: PublicKey, data: ByteVector, signed: ByteVector,
                          useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None): F[Boolean] =
    for
      algorithms <- Security.getAlgorithms[F](Signature)
      (algo, params) =
        if algorithms.contains(`RSASSA-PSS`.algorithm) && useLegacyName then
          (`RSASSA-PSS`, Some(algorithm.toPSSParameterSpec))
        else (algorithm.signature, None)
      flag <- Signature.publicKeyVerify[F](algo, key, data, signed, provider, params)
    yield flag
end `RSASSA-PSSOps`
