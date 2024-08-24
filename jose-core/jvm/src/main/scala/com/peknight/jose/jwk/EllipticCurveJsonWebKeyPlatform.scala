package com.peknight.jose.jwk

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import com.peknight.jose.jwk.ops.EllipticCurveKeyOps
import com.peknight.security.provider.Provider

import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait EllipticCurveJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: EllipticCurveJsonWebKey =>
  def publicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, PublicKey]] =
    val eitherT =
      for
        xCoordinate <- EitherT(self.xCoordinate.decodeToUnsignedBigInt[F])
        yCoordinate <- EitherT(self.yCoordinate.decodeToUnsignedBigInt[F])
        ecPublicKey <- EitherT(EllipticCurveKeyOps.toPublicKey[F](xCoordinate, yCoordinate,
          self.curve.std.ecParameterSpec, provider).map(_.asRight))
      yield
        ecPublicKey
    eitherT.value

  def privateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, Option[PrivateKey]]] =
    self.eccPrivateKey.fold(none[PrivateKey].asRight[DecodingFailure].pure[F]) { eccPrivateKey =>
      val eitherT =
        for
          eccPrivateKey <- EitherT(eccPrivateKey.decodeToUnsignedBigInt[F])
          ecPrivateKey <- EitherT(EllipticCurveKeyOps.toPrivateKey[F](
            eccPrivateKey, self.curve.std.ecParameterSpec, provider
          ).map(_.asRight))
        yield ecPrivateKey
      eitherT.value.map(_.map(_.some))
    }

  override def checkJsonWebKey[F[_]: Sync]: F[Either[DecodingFailure, Unit]] =
    val eitherT =
      for
        xCoordinate <- EitherT(self.xCoordinate.decodeToUnsignedBigInt[F])
        yCoordinate <- EitherT(self.yCoordinate.decodeToUnsignedBigInt[F])
        _ <- EitherT(EllipticCurveKeyOps.checkPointOnCurve(xCoordinate, yCoordinate, self.curve.std.ecParameterSpec)
          .left.map(DecodingFailure.apply).pure[F])
      yield
        ()
    eitherT.value
}
