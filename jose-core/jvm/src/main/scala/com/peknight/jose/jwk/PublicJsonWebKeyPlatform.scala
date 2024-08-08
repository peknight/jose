package com.peknight.jose.jwk

import cats.Apply
import cats.data.NonEmptyList
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
import com.peknight.jose.jwk.JsonWebKey.PublicJsonWebKey
import com.peknight.jose.key.X509Ops
import com.peknight.security.provider.Provider

import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.{KeyPair, PrivateKey, PublicKey}

trait PublicJsonWebKeyPlatform { self: PublicJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider] = None): F[Either[DecodingFailure, PublicKey]]
  def toPrivateKey[F[_]: Sync](provider: Option[Provider] = None): F[Either[DecodingFailure, Option[PrivateKey]]]
  def toKeyPair[F[_]: Sync](provider: Option[Provider] = None): F[Either[DecodingFailure, KeyPair]] =
    Apply[[X] =>> F[Either[DecodingFailure, X]]].map2(
      toPublicKey[F](provider),
      toPrivateKey[F](provider).map(_.flatMap(_.toRight(DecodingFailure(MissingPrivateKey))))
    )(new KeyPair(_, _))

  def checkForBareKeyCertMismatch[F[_]: Sync](publicKey: PublicKey, leafCertificate: Option[X509Certificate])
  : Either[JsonWebKeyError, PublicKey] =
    leafCertificate match
      case Some(cert) =>
        if Option(cert.getPublicKey).forall(_.equals(publicKey)) then publicKey.asRight
        else BareKeyCertMismatch(publicKey, cert).asLeft
      case None => publicKey.asRight

  def certificateChain[F[_]: Sync]: F[Either[DecodingFailure, Option[NonEmptyList[X509Certificate]]]] =
    X509Ops.certificateFactoryF[F].flatMap(certFactory =>
      self.x509CertificateChain.fold(none[NonEmptyList[X509Certificate]].asRight[DecodingFailure].pure[F])(
        _.map(baseToCertificate[F](_, certFactory)).sequence[[X] =>> F[Either[DecodingFailure, X]], X509Certificate]
          .map(_.map(_.some))
      )
    )

  def getLeafCertificate[F[_]: Sync]: F[Either[DecodingFailure, Option[X509Certificate]]] =
    X509Ops.certificateFactoryF[F].flatMap(certFactory => self.x509CertificateChain.map(_.head)
      .fold(none[X509Certificate].asRight[DecodingFailure].pure[F])(baseToCertificate[F](_, certFactory).map(_.map(_.some)))
    )

  def getLeafCertificate(x509CertificateChain: Option[NonEmptyList[X509Certificate]]): Option[X509Certificate] =
    x509CertificateChain.map(_.head)

  private def baseToCertificate[F[_]: Sync](base: Base, certFactory: CertificateFactory)
  : F[Either[DecodingFailure, X509Certificate]] =
    base.decode[F].flatMap {
      case Right(bytes) => X509Ops.fromBytes[F](bytes, certFactory).map(_.asRight[DecodingFailure])
      case Left(error) => error.asLeft[X509Certificate].pure[F]
    }
}
