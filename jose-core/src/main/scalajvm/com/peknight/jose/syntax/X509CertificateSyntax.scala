package com.peknight.jose.syntax

import cats.data.EitherT
import cats.effect.Sync
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asET
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-1`, `SHA-256`}
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.certificate.getEncodedF

import java.security.Provider as JProvider
import java.security.cert.X509Certificate

trait X509CertificateSyntax:
  extension (certificate: X509Certificate)
    def sha1Thumbprint[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Base64UrlNoPad]] =
      base64UrlThumbprint[F](`SHA-1`, provider)
    def sha256Thumbprint[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Base64UrlNoPad]] =
      base64UrlThumbprint[F](`SHA-256`, provider)
    def base64UrlThumbprint[F[_]: Sync](hashAlg: MessageDigestAlgorithm, provider: Option[Provider | JProvider] = None)
    : F[Either[Error, Base64UrlNoPad]] =
      val eitherT =
        for
          encoded <- certificate.getEncodedF[F].asET
          digest <- hashAlg.digest[F](encoded, provider).asET
        yield
          Base64UrlNoPad.fromByteVector(digest)
      eitherT.value
  end extension
end X509CertificateSyntax
object X509CertificateSyntax extends X509CertificateSyntax
