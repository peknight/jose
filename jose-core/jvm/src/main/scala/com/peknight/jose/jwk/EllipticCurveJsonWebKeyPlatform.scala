package com.peknight.jose.jwk

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import com.peknight.security.ecc.EC
import com.peknight.security.provider.Provider

import java.security.interfaces.{ECPrivateKey, ECPublicKey}
import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait EllipticCurveJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: EllipticCurveJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PublicKey]] =
    val either =
      for
        xCoordinate <- self.xCoordinate.decodeToUnsignedBigInt[Id]
        yCoordinate <- self.yCoordinate.decodeToUnsignedBigInt[Id]
      yield
        EC.publicKey[F](xCoordinate, yCoordinate, self.curve.ecParameterSpec, provider).map(_.asInstanceOf[PublicKey])
          .asError
    either.fold(_.asLeft.pure, identity)

  def toPrivateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Option[PrivateKey]]] =
    self.eccPrivateKey.fold(none[ECPrivateKey].asRight[Error].pure[F]) { eccPrivateKey =>
      eccPrivateKey.decodeToUnsignedBigInt[Id].fold(
        _.asLeft.pure,
        eccPrivateKey => EC.privateKey[F](eccPrivateKey, self.curve.ecParameterSpec, provider).asError
          .map(_.map(privateKey => privateKey.asInstanceOf[PrivateKey].some))
      )
    }

  override def handleCheckJsonWebKey: Either[Error, Unit] =
    for
      xCoordinate <- self.xCoordinate.decodeToUnsignedBigInt[Id]
      yCoordinate <- self.yCoordinate.decodeToUnsignedBigInt[Id]
      _ <- EC.checkPointOnCurve(xCoordinate, yCoordinate, self.curve.ecParameterSpec)
    yield
      ()
}
