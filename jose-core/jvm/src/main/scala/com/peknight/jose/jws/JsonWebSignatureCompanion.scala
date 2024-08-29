package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.jose.error.{MissingKey, UnsupportedSignatureAlgorithm}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.{SignaturePlatform, none}
import com.peknight.jose.jws.JsonWebSignature.{encodePayload, encodePayloadJson, toBytes}
import com.peknight.jose.jwx.{JoseHeader, toBase}
import com.peknight.security.error.InvalidSignature
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue
import io.circe.Json
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebSignatureCompanion:
  def signJson[F[_], A](header: JoseHeader, payload: A, key: Option[Key] = None, doKeyValidation: Boolean = true,
                        useLegacyName: Boolean = false, random: Option[SecureRandom] = None,
                        provider: Option[Provider | JProvider] = None)
                       (using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignature]] =
    encodePayloadJson(payload, header.isBase64UrlEncodePayload).fold(
      _.asLeft.pure[F],
      payload => sign[F](header, payload, key, doKeyValidation, useLegacyName, random, provider)
    )

  def signBytes[F[_]: Sync](header: JoseHeader, payload: ByteVector, key: Option[Key] = None,
                            doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                            random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, JsonWebSignature]] =
    encodePayload(payload, header.isBase64UrlEncodePayload).fold(
      _.asLeft.pure[F],
      payload => sign[F](header, payload, key, doKeyValidation, useLegacyName, random, provider)
    )

  def sign[F[_]: Sync](header: JoseHeader, payload: String, key: Option[Key] = None, doKeyValidation: Boolean = true,
                       useLegacyName: Boolean = false, random: Option[SecureRandom] = None,
                       provider: Option[Provider | JProvider] = None): F[Either[Error, JsonWebSignature]] =
    handleSignSignature[F, JsonWebSignature](header, payload, key, doKeyValidation, useLegacyName, random, provider)(
      (headerBase, signature) => JsonWebSignature(header, headerBase, payload, signature)
    )

  private[jws] def handleSignSignature[F[_]: Sync, S <: Signature](header: JoseHeader, payload: String,
                                                                   key: Option[Key] = None,
                                                                   doKeyValidation: Boolean = true,
                                                                   useLegacyName: Boolean = false,
                                                                   random: Option[SecureRandom] = None,
                                                                   provider: Option[Provider | JProvider] = None)
                                                                  (f: (Base64UrlNoPad, Base64UrlNoPad) => S)
  : F[Either[Error, S]] =
    val either =
      for
        headerBase <- toBase(header, Base64UrlNoPad)
        data <- toBytes(headerBase, payload)
      yield
        handleSign[F](header.algorithm, key, data, doKeyValidation, useLegacyName, random, provider).map(_.map(
          signature => f(headerBase, Base64UrlNoPad.fromByteVector(signature))
        ))
    either.fold(_.asLeft.pure, identity)

  def handleSign[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                             doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                             random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    algorithm match
      case Some(`none`) | None => none.sign(key, data, doKeyValidation).pure[F]
      case Some(algo: SignaturePlatform) =>
        key match
          case Some(k) => algo.signJws[F](k, data, doKeyValidation, useLegacyName, random, provider)
          case None => MissingKey.asLeft.pure[F]
      case Some(algo) => UnsupportedSignatureAlgorithm(algo).asLeft.pure[F]

  def handleVerify[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                               signed: ByteVector, doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                               provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    algorithm match
      case Some(`none`) | None => none.verify(key, data, signed, doKeyValidation).pure[F]
      case Some(algo: SignaturePlatform) =>
        key match
          case Some(k) => algo.verifyJws[F](k, data, signed, doKeyValidation, useLegacyName, provider)
          case None => MissingKey.asLeft.pure[F]
      case Some(algo) => UnsupportedSignatureAlgorithm(algo).asLeft.pure[F]

  def handleCheck[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                              signed: ByteVector, doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                              provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]] =
    handleVerify[F](algorithm, key, data, signed, doKeyValidation, useLegacyName, provider)
      .map(_.flatMap(isTrue(_, InvalidSignature)))
end JsonWebSignatureCompanion
