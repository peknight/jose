package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.JoseHeader
import com.peknight.jose.error.jws.{CharacterCodingError, JsonWebSignatureError, MissingKey}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.{HmacSHAAlgorithm, none}
import com.peknight.jose.jws.JsonWebSignature.{concat, toBase}
import com.peknight.security.crypto.Mac
import com.peknight.security.provider.Provider
import io.circe.Json
import scodec.bits.ByteVector

import java.security.{Key, Provider as JProvider}

trait JsonWebSignatureCompanion:
  def sign[F[_], A](header: JoseHeader, payload: A, key: Option[Key] = None,
                    provider: Option[Provider | JProvider] = None)
                   (using Sync[F], Encoder[Id, Json, A]): F[Either[JsonWebSignatureError, JsonWebSignature]] =
    val eitherT =
      for
        p <- EitherT(toBase(header, Base64UrlNoPad).pure[F])
        payload <- EitherT(toBase(payload, Base64UrlNoPad).pure[F])
        input <- EitherT(ByteVector.encodeUtf8(concat(p, payload)).left.map(CharacterCodingError.apply).pure[F])
        sig <- EitherT(handleSign[F](input, header.algorithm, key, provider))
      yield
        JsonWebSignature(header, p, payload, Base64UrlNoPad.fromByteVector(sig))
    eitherT.value

  def handleSign[F[_]: Sync](input: ByteVector, algorithm: Option[JsonWebAlgorithm], key: Option[Key],
                             provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, ByteVector]] =
    (algorithm, key) match
      case (None, _) => ByteVector.empty.asRight.pure
      case (Some(`none`), _) => ByteVector.empty.asRight.pure
      case (Some(algo: HmacSHAAlgorithm), Some(k)) =>
        Mac.mac[F](algo.mac, k, input, provider).map(_.asRight)
      case (Some(algo: HmacSHAAlgorithm), None) => MissingKey.asLeft.pure
      case _ => ???
end JsonWebSignatureCompanion
