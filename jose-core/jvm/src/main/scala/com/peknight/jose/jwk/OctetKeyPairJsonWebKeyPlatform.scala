package com.peknight.jose.jwk

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jwk.JsonWebKey.OctetKeyPairJsonWebKey
import com.peknight.jose.key.OctetKeyPairOps
import com.peknight.security.provider.Provider

import java.security.PublicKey

trait OctetKeyPairJsonWebKeyPlatform { self: OctetKeyPairJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider]): F[Either[DecodingFailure, PublicKey]] =
    self.xCoordinate.decode[F].flatMap {
      case Right(publicKeyBytes) =>
        OctetKeyPairOps.getKeyPairOps(self.curve)
          .toPublicKey[F](publicKeyBytes, self.curve.asInstanceOf, provider)
          .map(_.asRight[DecodingFailure])
      case Left(error) => error.asLeft[PublicKey].pure[F]
    }
}
