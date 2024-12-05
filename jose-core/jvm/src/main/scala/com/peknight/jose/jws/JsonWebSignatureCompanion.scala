package com.peknight.jose.jws

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.{Functor, Id}
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.jose.error.{MissingKey, UnsupportedSignatureAlgorithm}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.{SignaturePlatform, none}
import com.peknight.jose.jws.JsonWebSignature.{encodePayload, encodePayloadJson, encodePayloadString, toBytes}
import com.peknight.jose.jwx
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader, encodeToBase}
import com.peknight.security.error.InvalidSignature
import com.peknight.validation.std.either.isTrue
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.Charset
import java.security.Key

trait JsonWebSignatureCompanion:
  def signBytes[F[_]: Sync](header: JoseHeader, payload: ByteVector, key: Option[Key] = None,
                            configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebSignature]] =
    doHandleSign[F](header, key, configuration)(encodePayload(payload, _, _))

  def signString[F[_]: Sync](header: JoseHeader, payload: String, key: Option[Key] = None,
                             configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebSignature]] =
    doHandleSign[F](header, key, configuration)(encodePayloadString(payload, _, _))

  def signJson[F[_], A](header: JoseHeader, payload: A, key: Option[Key] = None,
                        configuration: JoseConfiguration = JoseConfiguration.default)
                       (using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignature]] =
    doHandleSign[F](header, key, configuration)(encodePayloadJson(payload, _, _))

  private def doHandleSign[F[_] : Sync](header: JoseHeader, key: Option[Key] = None,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
                                       (encodePayload: (Boolean, Charset) => Either[Error, String])
  : F[Either[Error, JsonWebSignature]] =
    encodePayload(header.isBase64UrlEncodePayload, configuration.charset).fold(
      _.asLeft.pure[F],
      payload => sign[F](header, payload, key, configuration)
    )

  def sign[F[_]: Sync](header: JoseHeader, payload: String, key: Option[Key] = None,
                       configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebSignature]] =
    handleSignSignature[F, JsonWebSignature](header, payload, key, configuration)(
      (headerBase, signature) => JsonWebSignature(header, headerBase, payload, signature)
    )

  private[jws] def handleSignSignature[F[_]: Sync, S <: Signature](header: JoseHeader, payload: String,
                                                                   key: Option[Key] = None,
                                                                   configuration: JoseConfiguration = JoseConfiguration.default)
                                                                  (f: (Base64UrlNoPad, Base64UrlNoPad) => S)
  : F[Either[Error, S]] =
    val either =
      for
        headerBase <- encodeToBase(header, Base64UrlNoPad, configuration.charset)
        data <- toBytes(headerBase, payload, configuration.charset)
      yield
        handleSign[F](header.algorithm, key, data, configuration).map(_.map(
          signature => f(headerBase, Base64UrlNoPad.fromByteVector(signature))
        ))
    either.fold(_.asLeft.pure, identity)

  def handleSign[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                             configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, ByteVector]] =
    algorithm match
      case Some(`none`) | None => none.sign(key, data, configuration.doKeyValidation).pure[F]
      case Some(algo: SignaturePlatform) =>
        key match
          case Some(k) =>
            algo.signJws[F](k, data, configuration.doKeyValidation, configuration.useLegacyName, configuration.random,
              configuration.signatureProvider)
          case None => MissingKey.asLeft.pure[F]
      case Some(algo) => UnsupportedSignatureAlgorithm(algo).asLeft.pure[F]

  def handleVerify[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                               signed: ByteVector, configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, Boolean]] =
    algorithm match
      case Some(`none`) | None => none.verify(key, data, signed, configuration.doKeyValidation).pure[F]
      case Some(algo: SignaturePlatform) =>
        key match
          case Some(k) =>
            algo.verifyJws[F](k, data, signed, configuration.doKeyValidation, configuration.useLegacyName,
              configuration.signatureProvider)
          case None => MissingKey.asLeft.pure[F]
      case Some(algo) => UnsupportedSignatureAlgorithm(algo).asLeft.pure[F]

  private[jws] def checkVerify[F[_]: Functor](eitherT: F[Either[Error, Boolean]]): F[Either[Error, Unit]] =
    eitherT.map(_.flatMap(isTrue(_, InvalidSignature)))
end JsonWebSignatureCompanion
