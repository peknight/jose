package com.peknight.jose.jwk

import cats.Apply
import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import com.peknight.cats.ext.instances.eitherT.given
import com.peknight.codec.base.Base
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.error.jwk.{BareKeyCertMismatch, JsonWebKeyError, MissingPrivateKey}
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jwk.ops.X509Ops
import com.peknight.security.provider.Provider

import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.{KeyPair, PrivateKey, PublicKey, Provider as JProvider}

trait AsymmetricJsonWebKeyPlatform { self: AsymmetricJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, PublicKey]]
  def toPrivateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, Option[PrivateKey]]]
  def toKeyPair[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, KeyPair]] =
    Apply[[X] =>> F[Either[DecodingFailure, X]]].map2(
      toPublicKey[F](provider),
      toPrivateKey[F](provider).map(_.flatMap(_.toRight(DecodingFailure(MissingPrivateKey))))
    )(new KeyPair(_, _))

  def isBareKeyCertMatched(publicKey: PublicKey, leafCertificate: Option[X509Certificate]): Boolean =
    leafCertificate.flatMap(cert => Option(cert.getPublicKey)).forall(_.equals(publicKey))

  def checkJsonWebKeyTyped[F[_]: Sync]: F[Either[DecodingFailure, Unit]] =
    ().asRight[DecodingFailure].pure[F]

  def checkJsonWebKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, Unit]] =
    val eitherT =
      for
        publicKey <- EitherT(toPublicKey[F](provider))
        leafCertificate <- EitherT(getLeafCertificate[F])
        _ <- EitherT(checkBareKeyCertMatched(publicKey, leafCertificate).left.map(DecodingFailure.apply).pure[F])
        _ <- EitherT(checkJsonWebKeyTyped[F])
      yield ()
    eitherT.value

  def checkBareKeyCertMatched(publicKey: PublicKey, leafCertificate: Option[X509Certificate])
  : Either[JsonWebKeyError, Unit] =
    leafCertificate match
      case Some(cert) =>
        if Option(cert.getPublicKey).forall(_.equals(publicKey)) then ().asRight
        else BareKeyCertMismatch(publicKey, cert).asLeft
      case None => ().asRight

  def certificateChain[F[_]: Sync]: F[Either[DecodingFailure, Option[NonEmptyList[X509Certificate]]]] =
    self.x509CertificateChain.fold(none[NonEmptyList[X509Certificate]].asRight[DecodingFailure].pure[F])(
      _.map(baseToCertificate[F]).sequence[[X] =>> F[Either[DecodingFailure, X]], X509Certificate]
          .map(_.map(_.some))
    )

  def getLeafCertificate[F[_]: Sync]: F[Either[DecodingFailure, Option[X509Certificate]]] =
    self.x509CertificateChain.map(_.head).fold(none[X509Certificate].asRight[DecodingFailure].pure[F])(
      baseToCertificate[F](_).map(_.map(_.some))
    )


  def getLeafCertificate(x509CertificateChain: Option[NonEmptyList[X509Certificate]]): Option[X509Certificate] =
    x509CertificateChain.map(_.head)

  private def baseToCertificate[F[_]: Sync](base: Base)
  : F[Either[DecodingFailure, X509Certificate]] =
    base.decode[F].flatMap {
      case Right(bytes) => X509Ops.fromBytes[F](bytes).map(_.asRight[DecodingFailure])
      case Left(error) => error.asLeft[X509Certificate].pure[F]
    }
}
