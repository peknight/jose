package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.security.cipher.RSA
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.provider.Provider

import java.security.spec.{RSAPrivateCrtKeySpec, RSAPrivateKeySpec, RSAPublicKeySpec}
import java.security.{KeyPair, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

object RSAKeyOps extends KeyPairOps:
  def keyAlgorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm = RSA

  def toPublicKey[F[_]: Sync](modulus: BigInt, publicExponent: BigInt, provider: Option[Provider | JProvider] = None): F[PublicKey] =
    generatePublic[F](new RSAPublicKeySpec(modulus.bigInteger, publicExponent.bigInteger), provider)

  def toPrivateKey[F[_]: Sync](modulus: BigInt, privateExponent: BigInt, provider: Option[Provider | JProvider] = None)
  : F[PrivateKey] =
    generatePrivate[F](new RSAPrivateKeySpec(modulus.bigInteger, privateExponent.bigInteger), provider)

  def toPrivateKey[F[_]: Sync](modulus: BigInt, publicExponent: BigInt, privateExponent: BigInt, primeP: BigInt,
                               primeQ: BigInt, primeExponentP: BigInt, primeExponentQ: BigInt, crtCoefficient: BigInt,
                               provider: Option[Provider | JProvider]): F[PrivateKey] =
    generatePrivate[F](
      new RSAPrivateCrtKeySpec(modulus.bigInteger, publicExponent.bigInteger,
        privateExponent.bigInteger, primeP.bigInteger, primeQ.bigInteger, primeExponentP.bigInteger,
        primeExponentQ.bigInteger, crtCoefficient.bigInteger
      ),
      provider
    )
end RSAKeyOps
