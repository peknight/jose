package com.peknight.jose.jwk

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import cats.{Apply, Id}
import com.peknight.cats.ext.instances.eitherT.given
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.{BareKeyCertMismatch, JoseError, MissingPrivateKey}
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.security.certificate.factory.X509
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue

import java.security.cert.X509Certificate
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
      bytes => X509.generateX509CertificateFromBytes[F](bytes, provider).asError
    )

  private def checkBareKeyCertMatched(publicKey: PublicKey, leafCertificate: Option[X509Certificate])
  : Either[JoseError, Unit] =
    leafCertificate match
      case Some(cert) => isTrue(Option(cert.getPublicKey).forall(_.equals(publicKey)), BareKeyCertMismatch(publicKey, cert))
      case None => ().asRight

}
