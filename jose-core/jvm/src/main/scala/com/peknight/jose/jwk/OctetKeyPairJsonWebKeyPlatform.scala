package com.peknight.jose.jwk

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jwk.JsonWebKey.OctetKeyPairJsonWebKey
import com.peknight.jose.key.OctetKeyPairOps
import com.peknight.security.provider.Provider

import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait OctetKeyPairJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: OctetKeyPairJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, PublicKey]] =
    self.xCoordinate.decode[F].flatMap {
      case Right(publicKeyBytes) =>
        OctetKeyPairOps.getKeyPairOps(self.curve)
          .toPublicKey[F](publicKeyBytes, self.curve.asInstanceOf, provider)
          .map(_.asRight[DecodingFailure])
      case Left(error) => error.asLeft[PublicKey].pure[F]
    }

  def toPrivateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, Option[PrivateKey]]] =
    self.eccPrivateKey.fold(none[PrivateKey].asRight[DecodingFailure].pure[F]) { eccPrivateKey =>
      eccPrivateKey.decode[F].flatMap {
        case Right(privateKeyBytes) =>
          OctetKeyPairOps.getKeyPairOps(self.curve)
            .toPrivateKey[F](privateKeyBytes, self.curve.asInstanceOf, provider)
            .map(_.some.asRight[DecodingFailure])
        case Left(error) => error.asLeft[Option[PrivateKey]].pure[F]
      }
    }
}
