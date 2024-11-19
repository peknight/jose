package com.peknight.jose.jwk

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-256`}
import com.peknight.security.provider.Provider
import org.http4s.Uri
import scodec.bits.ByteVector

import java.security.Provider as JProvider

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
}
