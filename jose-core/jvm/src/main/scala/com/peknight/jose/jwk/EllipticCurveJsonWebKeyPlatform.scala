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
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.ecParameterSpec.{checkPointOnCurve, privateKey, publicKey}

import java.security.interfaces.ECPrivateKey
import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait EllipticCurveJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: EllipticCurveJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PublicKey]] =
    val either =
      for
        xCoordinate <- self.xCoordinate.decodeToUnsignedBigInt[Id]
        yCoordinate <- self.yCoordinate.decodeToUnsignedBigInt[Id]
      yield
        self.curve.ecParameterSpec.publicKey[F](xCoordinate, yCoordinate, provider).map(_.asInstanceOf[PublicKey])
          .asError
    either.fold(_.asLeft.pure, identity)

  def toPrivateKeyOption[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Option[PrivateKey]]] =
    self.eccPrivateKey.fold(none[ECPrivateKey].asRight[Error].pure[F]) { eccPrivateKey =>
      eccPrivateKey.decodeToUnsignedBigInt[Id].fold(
        _.asLeft.pure,
        eccPrivateKey => self.curve.ecParameterSpec.privateKey[F](eccPrivateKey, provider).asError
          .map(_.map(privateKey => privateKey.asInstanceOf[PrivateKey].some))
      )
    }

  override def handleCheckJsonWebKey: Either[Error, Unit] =
    for
      xCoordinate <- self.xCoordinate.decodeToUnsignedBigInt[Id]
      yCoordinate <- self.yCoordinate.decodeToUnsignedBigInt[Id]
      _ <- self.curve.ecParameterSpec.checkPointOnCurve(xCoordinate, yCoordinate)
    yield
      ()
}
