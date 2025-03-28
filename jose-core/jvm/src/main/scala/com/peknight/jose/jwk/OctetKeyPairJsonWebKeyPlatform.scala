package com.peknight.jose.jwk

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.UnsupportedKeyAlgorithm
import com.peknight.jose.jwk.JsonWebKey.OctetKeyPairJsonWebKey
import com.peknight.security.key.agreement.XDH
import com.peknight.security.provider.Provider
import com.peknight.security.signature.EdDSA

import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait OctetKeyPairJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: OctetKeyPairJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PublicKey]] =
    self.xCoordinate.decode[Id].map { publicKeyBytes =>
      self.curve match
        case edDSA: EdDSA => edDSA.publicKey[F](publicKeyBytes, provider).map(_.asInstanceOf[PublicKey]).asError
        case xdh: XDH => xdh.publicKey[F](publicKeyBytes, provider).map(_.asInstanceOf[PublicKey]).asError
        case curve => UnsupportedKeyAlgorithm(curve.parameterSpecName).asLeft.pure
    }.fold(_.asLeft.pure, identity)

  def toPrivateKeyOption[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Option[PrivateKey]]] =
    self.eccPrivateKey.fold(none[PrivateKey].asRight[Error].pure[F]) { eccPrivateKey =>
      eccPrivateKey.decode[Id].map { privateKeyBytes =>
        self.curve match
          case edDSA: EdDSA => edDSA.privateKey[F](privateKeyBytes, provider)
            .map(privateKey => privateKey.asInstanceOf[PrivateKey].some).asError
          case xdh: XDH => xdh.privateKey[F](privateKeyBytes, provider)
            .map(privateKey => privateKey.asInstanceOf[PrivateKey].some).asError
          case curve => UnsupportedKeyAlgorithm(curve.parameterSpecName).asLeft.pure
      }.fold(_.asLeft.pure, identity)
    }
}
