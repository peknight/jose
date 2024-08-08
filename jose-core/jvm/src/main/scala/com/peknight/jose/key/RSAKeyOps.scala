package com.peknight.jose.key

import cats.effect.Sync
import com.peknight.security.cipher.RSA
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.provider.Provider

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{RSAPrivateCrtKeySpec, RSAPrivateKeySpec, RSAPublicKeySpec}

object RSAKeyOps extends KeyPairOps:
  def keyFactoryAlgorithm: KeyFactoryAlgorithm = RSA

  def toPublicKey[F[_]: Sync](modulus: BigInt, publicExponent: BigInt, provider: Option[Provider]): F[RSAPublicKey] =
    generatePublicKey[F, RSAPublicKey](new RSAPublicKeySpec(modulus.bigInteger, publicExponent.bigInteger), provider)

  def toPrivateKey[F[_]: Sync](modulus: BigInt, privateExponent: BigInt, provider: Option[Provider]): F[RSAPrivateKey] =
    generatePrivateKey[F, RSAPrivateKey](new RSAPrivateKeySpec(modulus.bigInteger, privateExponent.bigInteger), provider)

  def toPrivateKey[F[_]: Sync](modulus: BigInt, publicExponent: BigInt, privateExponent: BigInt, primeP: BigInt,
                               primeQ: BigInt, primeExponentP: BigInt, primeExponentQ: BigInt, crtCoefficient: BigInt,
                               provider: Option[Provider]): F[RSAPrivateKey] =
    generatePrivateKey[F, RSAPrivateKey](
      new RSAPrivateCrtKeySpec(modulus.bigInteger, publicExponent.bigInteger,
        privateExponent.bigInteger, primeP.bigInteger, primeQ.bigInteger, primeExponentP.bigInteger,
        primeExponentQ.bigInteger, crtCoefficient.bigInteger
      ),
      provider
    )
end RSAKeyOps
