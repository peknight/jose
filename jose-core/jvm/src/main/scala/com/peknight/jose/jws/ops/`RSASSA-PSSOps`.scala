package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.error.jws.JsonWebSignatureError
import com.peknight.jose.jwa.signature.`RSASSA-PSSAlgorithm`
import com.peknight.security.Security
import com.peknight.security.provider.Provider
import com.peknight.security.signature.{Signature, SignatureAlgorithm, `RSASSA-PSS`}
import scodec.bits.ByteVector

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.AlgorithmParameterSpec
import java.security.{SecureRandom, Provider as JProvider}

object `RSASSA-PSSOps` extends RSASSAOps[`RSASSA-PSSAlgorithm`]:

  def typedSign[F[_] : Sync](algorithm: `RSASSA-PSSAlgorithm`, key: RSAPrivateKey, data: ByteVector,
                             useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                             random: Option[SecureRandom] = None): F[Either[JsonWebSignatureError, ByteVector]] =
    for
      algorithms <- Security.getAlgorithms[F](Signature)
      (algo, params) = getAlgorithmAndParams(algorithm, useLegacyName, algorithms)
      signed <- Signature.sign[F](algo, key, data, provider, params, random)
    yield signed.asRight

  def typedVerify[F[_] : Sync](algorithm: `RSASSA-PSSAlgorithm`, key: RSAPublicKey, data: ByteVector, signed: ByteVector,
                               useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    for
      algorithms <- Security.getAlgorithms[F](Signature)
      (algo, params) = getAlgorithmAndParams(algorithm, useLegacyName, algorithms)
      flag <- Signature.publicKeyVerify[F](algo, key, data, signed, provider, params)
    yield flag.asRight

  private def getAlgorithmAndParams(algorithm: `RSASSA-PSSAlgorithm`, useLegacyName: Boolean, algorithms: Set[String])
  : (SignatureAlgorithm, Option[AlgorithmParameterSpec]) =
    if algorithms.contains(`RSASSA-PSS`.algorithm) && !useLegacyName then
      (`RSASSA-PSS`, Some(algorithm.toPSSParameterSpec))
    else (algorithm.signature, None)

end `RSASSA-PSSOps`
