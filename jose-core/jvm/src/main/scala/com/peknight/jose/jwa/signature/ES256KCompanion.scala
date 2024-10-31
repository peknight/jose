package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.jwa.ecc.`P-256K`
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import scodec.bits.ByteVector

trait ES256KCompanion extends ECDSAPlatform:
  override def isAvailable[F[_]: Sync]: F[Boolean] = super.isAvailable.flatMap {
    case true =>
      val jwk = EllipticCurveJsonWebKey(`P-256K`,
        Base64UrlNoPad.unsafeFromString("gi0g9DzM2SvjVV7iD_upIU0urmZRjpoIc4Efu8563y8"),
        Base64UrlNoPad.unsafeFromString("Y5K6GofrdlWNLlfT8-AEyJyVZ3yJJcGgkGroHQCAhmk"),
        Some(Base64UrlNoPad.unsafeFromString("Vd99BKh6pxt3mXSDJzHuVrCq52xBXAKVahbuFb6dqBc"))
      )
      jwk.privateKey[F]().flatMap {
        case Right(Some(privateKey)) => handleSign[F](privateKey, ByteVector(2, 6)).map(_.isRight)
        case _ => false.pure[F]
      }
    case false => false.pure[F]
  }
end ES256KCompanion
