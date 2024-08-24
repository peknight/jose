package com.peknight.jose.jwk

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.applicativeError.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import cats.{Apply, Id}
import com.peknight.cats.ext.instances.eitherT.given
import com.peknight.codec.base.Base
import com.peknight.codec.error.DecodingFailure
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.jwk.{BareKeyCertMismatch, JsonWebKeyError, MissingPrivateKey}
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jwk.ops.X509Ops
import com.peknight.security.certificate.factory.X509
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue

import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.{KeyPair, PrivateKey, PublicKey, Provider as JProvider}

trait AsymmetricJsonWebKeyPlatform { self: AsymmetricJsonWebKey =>
  def publicKey[F[+_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PublicKey]]
  def privateKey[F[+_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Option[PrivateKey]]]
  def keyPair[F[+_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, KeyPair]] =
    Apply[[X] =>> F[Either[Error, X]]].map2(
      publicKey[F](provider),
      privateKey[F](provider).map(_.flatMap(_.toRight(MissingPrivateKey)))
    )(new KeyPair(_, _))
  protected def checkJsonWebKey[F[_]: Sync]: F[Either[Error, Unit]] = ().asRight[Error].pure[F]
  def checkJsonWebKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]] =
    val eitherT =
      for
        publicKey <- EitherT(publicKey[F](provider))
        leafCertificate <- EitherT(getLeafCertificate[F](provider))
        _ <- EitherT(checkBareKeyCertMatched(publicKey, leafCertificate).pure[F])
        _ <- EitherT(checkJsonWebKey[F])
      yield ()
    eitherT.value


  def certificateChain[F[_]: Sync](provider: Option[Provider | JProvider] = None)
  : F[Either[Error, Option[NonEmptyList[X509Certificate]]]] =
    self.x509CertificateChain.fold(none[NonEmptyList[X509Certificate]].asRight[Error].pure[F])(
      _.map(baseToCertificate[F](_, provider))
        .sequence[[X] =>> F[Either[Error, X]], X509Certificate]
        .map(_.map(_.some))
    )

  def getLeafCertificate[F[_]: Sync](provider: Option[Provider | JProvider] = None)
  : F[Either[Error, Option[X509Certificate]]] =
    self.x509CertificateChain.map(_.head).fold(none[X509Certificate].asRight[Error].pure[F])(
      baseToCertificate[F](_, provider).map(_.map(_.some))
    )

  private def baseToCertificate[F[_]: Sync](base: Base, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, X509Certificate]] =
    base.decode[Id].fold(
      _.asLeft.pure,
      bytes => X509.generateCertificateFromBytes[F](bytes, provider).attempt.map(_.asError)
    )

  private def checkBareKeyCertMatched(publicKey: PublicKey, leafCertificate: Option[X509Certificate])
  : Either[JsonWebKeyError, Unit] =
    leafCertificate match
      case Some(cert) => isTrue(Option(cert.getPublicKey).forall(_.equals(publicKey)), BareKeyCertMismatch(publicKey, cert))
      case None => ().asRight

}
