package com.peknight.jose.jwk

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.error.jwk.NoSuchCurve
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import com.peknight.jose.key.{BigIntOps, EllipticCurveKeyOps}
import com.peknight.security.provider.Provider

import java.security.spec.ECParameterSpec
import java.security.{PrivateKey, PublicKey}

trait EllipticCurveJsonWebKeyPlatform extends PublicJsonWebKeyPlatform { self: EllipticCurveJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider] = None): F[Either[DecodingFailure, PublicKey]] =
    val eitherT =
      for
        xCoordinate <- EitherT(self.xCoordinate.decode[F])
        yCoordinate <- EitherT(self.yCoordinate.decode[F])
        spec <- EitherT(getEcParameterSpec.toRight(DecodingFailure(NoSuchCurve)).pure[F])
        ecPublicKey <- EitherT(EllipticCurveKeyOps.toPublicKey[F](
          BigIntOps.fromBytes(xCoordinate), BigIntOps.fromBytes(yCoordinate), spec, provider
        ).map(_.asRight))
      yield
        ecPublicKey
    eitherT.value

  def toPrivateKey[F[_]: Sync](provider: Option[Provider] = None): F[Either[DecodingFailure, Option[PrivateKey]]] =
    self.eccPrivateKey.fold(none[PrivateKey].asRight[DecodingFailure].pure[F]) { eccPrivateKey =>
      val eitherT =
        for
          eccPrivateKey <- EitherT(eccPrivateKey.decode[F])
          spec <- EitherT(getEcParameterSpec.toRight(DecodingFailure(NoSuchCurve)).pure[F])
          ecPrivateKey <- EitherT(EllipticCurveKeyOps.toPrivateKey[F](
            BigIntOps.fromBytes(eccPrivateKey), spec, provider
          ).map(_.asRight))
        yield ecPrivateKey
      eitherT.value.map(_.map(_.some))
    }

  private def getEcParameterSpec: Option[ECParameterSpec] = Curve.curveList.find(_ == self.curve).map(_.ecParameterSpec)

  override def checkJsonWebKeyTyped[F[_]: Sync]: F[Either[DecodingFailure, Unit]] =
    val eitherT =
      for
        xCoordinate <- EitherT(self.xCoordinate.decode[F])
        yCoordinate <- EitherT(self.yCoordinate.decode[F])
        spec <- EitherT(getEcParameterSpec.toRight(DecodingFailure(NoSuchCurve)).pure[F])
        _ <- EitherT(EllipticCurveKeyOps.checkPointOnCurve(
          BigIntOps.fromBytes(xCoordinate), BigIntOps.fromBytes(yCoordinate), spec
        ).left.map(DecodingFailure.apply).pure[F])
      yield
        ()
    eitherT.value
}
