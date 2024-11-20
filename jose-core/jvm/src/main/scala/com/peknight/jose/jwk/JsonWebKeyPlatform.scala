package com.peknight.jose.jwk

import cats.Id
import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import com.peknight.cats.ext.instances.eitherT.given
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.{Base, Base64UrlNoPad}
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.{BareKeyCertMismatch, JoseError}
import com.peknight.jose.syntax.x509Certificate.base64UrlThumbprint
import com.peknight.security.certificate.factory.X509
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-1`, `SHA-256`}
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue
import org.http4s.Uri
import scodec.bits.ByteVector

import java.security.cert.X509Certificate
import java.security.{PublicKey, Provider as JProvider}

trait JsonWebKeyPlatform { self: JsonWebKey =>

  def calculateThumbprint[F[_]: Sync](hashAlgorithm: MessageDigestAlgorithm = `SHA-256`,
                                      provider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]] =
    val eitherT =
      for
        input <- ByteVector.encodeUtf8(self.thumbprintHashInput).asError.eLiftET[F]
        output <- EitherT(hashAlgorithm.digest[F](input, provider).asError)
      yield
        output
    eitherT.value

  def calculateBase64UrlEncodedThumbprint[F[_]: Sync](hashAlgorithm: MessageDigestAlgorithm = `SHA-256`,
                                                      provider: Option[Provider | JProvider] = None
                                                     ): F[Either[Error, Base64UrlNoPad]] =
    calculateThumbprint[F](hashAlgorithm, provider).map(_.map(Base64UrlNoPad.fromByteVector))

  def calculateThumbprintUri[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Uri]] =
    calculateBase64UrlEncodedThumbprint[F](`SHA-256`, provider).map(_.flatMap(thumbprint =>
      Uri.fromString(s"urn:ietf:params:oauth:jwk-thumbprint:sha-256:${thumbprint.value}").asError
    ))

  def getX509CertificateChain[F[_]: Sync](provider: Option[Provider | JProvider] = None)
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

  def getX509CertificateSHA1Thumbprint[F[_]: Sync](certificateFactoryProvider: Option[Provider | JProvider] = None,
                                                   messageDigestProvider: Option[Provider | JProvider] = None)
  : F[Either[Error, Option[Base64UrlNoPad]]] =
    getX509CertificateThumbprint[F](self.x509CertificateSHA1Thumbprint, `SHA-1`, certificateFactoryProvider,
      messageDigestProvider)

  def getX509CertificateSHA256Thumbprint[F[_]: Sync](certificateFactoryProvider: Option[Provider | JProvider] = None,
                                                     messageDigestProvider: Option[Provider | JProvider] = None)
  : F[Either[Error, Option[Base64UrlNoPad]]] =
    getX509CertificateThumbprint[F](self.x509CertificateSHA256Thumbprint, `SHA-256`, certificateFactoryProvider,
      messageDigestProvider)

  private def getX509CertificateThumbprint[F[_]: Sync](thumbprint: Option[Base64UrlNoPad],
                                                       hashAlgo: MessageDigestAlgorithm,
                                                       certificateFactoryProvider: Option[Provider | JProvider] = None,
                                                       messageDigestProvider: Option[Provider | JProvider] = None)
  : F[Either[Error, Option[Base64UrlNoPad]]] =
    thumbprint match
      case Some(value) => value.some.asRight.pure
      case None => getLeafCertificate[F](certificateFactoryProvider).flatMap {
        case Right(Some(certificate)) =>
          certificate.base64UrlThumbprint[F](hashAlgo, messageDigestProvider).map(_.map(_.some))
        case Right(None) => none.asRight.pure
        case Left(error) => error.asLeft.pure
      }

  private def baseToCertificate[F[_]: Sync](base: Base, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, X509Certificate]] =
    base.decode[Id].fold(
      _.asLeft.pure,
      bytes => X509.generateX509CertificateFromBytes[F](bytes, provider).asError
    )

  protected def checkBareKeyCertMatched(publicKey: PublicKey, leafCertificate: Option[X509Certificate])
  : Either[JoseError, Unit] =
    leafCertificate match
      case Some(cert) =>
        isTrue(Option(cert.getPublicKey).forall(_.equals(publicKey)), BareKeyCertMismatch(publicKey, cert))
      case None => ().asRight
}
