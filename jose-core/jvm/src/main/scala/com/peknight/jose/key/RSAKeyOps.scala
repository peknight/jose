package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.security.cipher.RSA
import com.peknight.security.syntax.keyPairGenerator.{generateKeyPairF, initializeF}
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.provider.Provider

import java.security.spec.{RSAPrivateCrtKeySpec, RSAPrivateKeySpec, RSAPublicKeySpec}
import java.security.{KeyPair, PrivateKey, PublicKey, SecureRandom}

object RSAKeyOps extends KeyPairOps:
  def keyAlgorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm = RSA

  def toPublicKey[F[_]: Sync](modulus: BigInt, publicExponent: BigInt, provider: Option[Provider] = None): F[PublicKey] =
    generatePublicKey[F](new RSAPublicKeySpec(modulus.bigInteger, publicExponent.bigInteger), provider)

  def toPrivateKey[F[_]: Sync](modulus: BigInt, privateExponent: BigInt, provider: Option[Provider] = None)
  : F[PrivateKey] =
    generatePrivateKey[F](new RSAPrivateKeySpec(modulus.bigInteger, privateExponent.bigInteger), provider)

  def toPrivateKey[F[_]: Sync](modulus: BigInt, publicExponent: BigInt, privateExponent: BigInt, primeP: BigInt,
                               primeQ: BigInt, primeExponentP: BigInt, primeExponentQ: BigInt, crtCoefficient: BigInt,
                               provider: Option[Provider]): F[PrivateKey] =
    generatePrivateKey[F](
      new RSAPrivateCrtKeySpec(modulus.bigInteger, publicExponent.bigInteger,
        privateExponent.bigInteger, primeP.bigInteger, primeQ.bigInteger, primeExponentP.bigInteger,
        primeExponentQ.bigInteger, crtCoefficient.bigInteger
      ),
      provider
    )
  def generateKeyPair[F[_]: Sync](bits: Int, provider: Option[Provider] = None,
                                  secureRandom: Option[SecureRandom] = None): F[KeyPair] =
    for
      generator <- keyPairGenerator[F](provider)
      _ <- generator.initializeF[F](bits, secureRandom)
      keyPair <- generator.generateKeyPairF[F]
    yield keyPair
end RSAKeyOps
