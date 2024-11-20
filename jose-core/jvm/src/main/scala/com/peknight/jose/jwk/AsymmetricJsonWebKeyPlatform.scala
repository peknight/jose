package com.peknight.jose.jwk

import cats.Apply
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.cats.ext.instances.eitherT.given
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.jose.error.MissingPrivateKey
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.security.provider.Provider

import java.security.{KeyPair, PrivateKey, PublicKey, Provider as JProvider}

trait AsymmetricJsonWebKeyPlatform { self: AsymmetricJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PublicKey]]
  def toPrivateKeyOption[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Option[PrivateKey]]]
  def toPrivateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PrivateKey]] =
    toPrivateKeyOption[F](provider).map(_.flatMap(_.toRight(MissingPrivateKey)))
  def toKeyPair[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, KeyPair]] =
    Apply[[X] =>> F[Either[Error, X]]].map2(toPublicKey[F](provider), toPrivateKey[F](provider))(new KeyPair(_, _))

  protected def handleCheckJsonWebKey: Either[Error, Unit] = ().asRight[Error]

  def checkJsonWebKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]] =
    val eitherT =
      for
        publicKey <- EitherT(toPublicKey[F](provider))
        leafCertificate <- EitherT(getLeafCertificate[F](provider))
        _ <- checkBareKeyCertMatched(publicKey, leafCertificate).eLiftET
        _ <- handleCheckJsonWebKey.eLiftET
      yield ()
    eitherT.value
}
