package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.JoseHeader
import com.peknight.jose.error.jws.*
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.none
import com.peknight.jose.jws.JsonWebSignature.{toBase, toBytes}
import com.peknight.jose.jws.ops.{NoneOps, SignatureOps}
import com.peknight.security.provider.Provider
import io.circe.Json
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebSignatureCompanion:
  def signJson[F[_], A](header: JoseHeader, payload: A, key: Option[Key] = None, doKeyValidation: Boolean = true,
                        useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                        random: Option[SecureRandom] = None)
                       (using Sync[F], Encoder[Id, Json, A]): F[Either[JsonWebSignatureError, JsonWebSignature]] =
    toBytes(payload) match
      case Left(error) => error.asLeft.pure[F]
      case Right(payload) => sign[F](header, payload, key, doKeyValidation, useLegacyName, provider, random)

  def sign[F[_]](header: JoseHeader, payload: ByteVector, key: Option[Key] = None, doKeyValidation: Boolean = true,
                 useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                 random: Option[SecureRandom] = None)
                (using Sync[F]): F[Either[JsonWebSignatureError, JsonWebSignature]] =
    val eitherT =
      for
        headerBase <- EitherT(toBase(header, Base64UrlNoPad).pure[F])
        payloadBase = Base64UrlNoPad.fromByteVector(payload)
        input <- EitherT(toBytes(headerBase, payloadBase).pure[F])
        sig <- EitherT(handleSign[F](header.algorithm, key, input, doKeyValidation, useLegacyName, provider, random))
      yield
        JsonWebSignature(header, headerBase, payloadBase, Base64UrlNoPad.fromByteVector(sig))
    eitherT.value

  def handleSign[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                             doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                             provider: Option[Provider | JProvider] = None, random: Option[SecureRandom] = None)
  : F[Either[JsonWebSignatureError, ByteVector]] =
    algorithm match
      case Some(`none`) | None => NoneOps.sign(key, data, doKeyValidation).pure[F]
      case Some(algo) =>
        key match
          case Some(k) => SignatureOps.getSignatureOps(algo).map(_.sign[F](algo, k, data, doKeyValidation,
            useLegacyName, provider, random)).fold(_.asLeft.pure[F], identity)
          case None => MissingKey.asLeft.pure[F]

  def handleVerify[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                               signed: ByteVector, doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                               provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    algorithm match
      case Some(`none`) | None => NoneOps.verify(key, data, signed, doKeyValidation).pure[F]
      case Some(algo) =>
        key match
          case Some(k) => SignatureOps.getSignatureOps(algo).map(_.verify[F](algo, k, data, signed, doKeyValidation,
            useLegacyName, provider)).fold(_.asLeft.pure[F], identity)
          case None => MissingKey.asLeft.pure[F]
end JsonWebSignatureCompanion
