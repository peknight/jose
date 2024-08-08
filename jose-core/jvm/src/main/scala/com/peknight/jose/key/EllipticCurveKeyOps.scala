package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, PointNotOnCurve}
import com.peknight.security.ecc.EC
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.keyPairGenerator.{generateKeyPairF, initializeF}

import java.security.spec.*
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

  def isPointOnCurve(x: BigInt, y: BigInt, ecParameterSpec: ECParameterSpec): Boolean =
    val curve = ecParameterSpec.getCurve
    val a = BigInt(curve.getA)
    val b = BigInt(curve.getB)
    val p = BigInt(curve.getField.asInstanceOf[ECFieldFp].getP)
    val leftSide = y.pow(2).mod(p)
    val rightSide = (x.pow(3) + (a * x) + b).mod(p)
    leftSide == rightSide

  def checkPointOnCurve(x: BigInt, y: BigInt, ecParameterSpec: ECParameterSpec): Either[JsonWebKeyError, Unit] =
    if isPointOnCurve(x, y, ecParameterSpec) then ().asRight
    else PointNotOnCurve(x, y, ecParameterSpec).asLeft
end EllipticCurveKeyOps
