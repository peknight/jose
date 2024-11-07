package com.peknight.jose.jwa.signature

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.jwa.ecc.`P-256K`
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import scodec.bits.ByteVector

trait ES256KCompanion extends ECDSAPlatform { self: ECDSA =>
  override def isAvailable[F[_]: Sync]: F[Boolean] = super.isAvailable.flatMap {
    case true =>
      val xCoordinate = "gi0g9DzM2SvjVV7iD_upIU0urmZRjpoIc4Efu8563y8"
      val yCoordinate = "Y5K6GofrdlWNLlfT8-AEyJyVZ3yJJcGgkGroHQCAhmk"
      val eccPrivateKey = "Vd99BKh6pxt3mXSDJzHuVrCq52xBXAKVahbuFb6dqBc"
      val eitherT =
        for
          xCoordinate <- Base64UrlNoPad.fromString(xCoordinate).eLiftET[F]
          yCoordinate <- Base64UrlNoPad.fromString(yCoordinate).eLiftET[F]
          eccPrivateKey <- Base64UrlNoPad.fromString(eccPrivateKey).eLiftET[F]
          jwk = EllipticCurveJsonWebKey(`P-256K`, xCoordinate, yCoordinate, Some(eccPrivateKey))
          privateKey <- EitherT(jwk.toPrivateKey[F]())
          _ <- EitherT(handleSign[F](privateKey, ByteVector(2, 6)))
        yield ()
      eitherT.value.map(_.isRight)
    case false => false.pure[F]
  }
}
