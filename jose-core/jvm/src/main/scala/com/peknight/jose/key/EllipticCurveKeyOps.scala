package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.security.ecc.EC
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.syntax.keyPairGenerator.{initializeF, generateKeyPairF}
import com.peknight.security.provider.Provider

import java.security.spec.{ECParameterSpec, ECPoint, ECPrivateKeySpec, ECPublicKeySpec}
import java.security.{KeyPair, PrivateKey, PublicKey, SecureRandom}

object EllipticCurveKeyOps extends KeyPairOps:
  def keyAlgorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm = EC

  def toPublicKey[F[_]: Sync](x: BigInt, y: BigInt, spec: ECParameterSpec, provider: Option[Provider] = None)
  : F[PublicKey] =
    val w = new ECPoint(x.bigInteger, y.bigInteger)
    val ecPublicKeySpec = new ECPublicKeySpec(w, spec)
    generatePublicKey[F](ecPublicKeySpec, provider)

  def toPrivateKey[F[_]: Sync](d: BigInt, spec: ECParameterSpec, provider: Option[Provider] = None): F[PrivateKey] =
    generatePrivateKey[F](new ECPrivateKeySpec(d.bigInteger, spec), provider)

  def generateKeyPair[F[_]: Sync](spec: ECParameterSpec, provider: Option[Provider] = None,
                                  secureRandom: Option[SecureRandom] = None): F[KeyPair] =
    for
      generator <- keyPairGenerator[F](provider)
      _ <- generator.initializeF[F](spec, secureRandom)
      keyPair <- generator.generateKeyPairF[F]
    yield keyPair

end EllipticCurveKeyOps
