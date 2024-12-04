package com.peknight.jose.jws

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.{Functor, Id}
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.{MissingKey, UnsupportedSignatureAlgorithm}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.{SignaturePlatform, none}
import com.peknight.jose.jws.JsonWebSignature.{encodePayload, encodePayloadJson, encodePayloadString, toBytes}
import com.peknight.jose.jwx
import com.peknight.jose.jwx.{JoseContext, JoseHeader, encodeToBase}
import com.peknight.security.error.InvalidSignature
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebSignatureCompanion:
  def signBytes[F[_]: Sync](header: JoseHeader, payload: ByteVector, key: Option[Key] = None,
                            context: JoseContext = JoseContext.default)
  : F[Either[Error, JsonWebSignature]] =
    doHandleSign[F](header, key, context)(encodePayload(payload, _, _))

  def signString[F[_]: Sync](header: JoseHeader, payload: String, key: Option[Key] = None,
                             context: JoseContext = JoseContext.default)
  : F[Either[Error, JsonWebSignature]] =
    doHandleSign[F](header, key, context)(encodePayloadString(payload, _, _))

  def signJson[F[_], A](header: JoseHeader, payload: A, key: Option[Key] = None,
                        context: JoseContext = JoseContext.default)
                       (using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignature]] =
    doHandleSign[F](header, key, context)(encodePayloadJson(payload, _, _))

  private def doHandleSign[F[_] : Sync](header: JoseHeader, key: Option[Key] = None,
                                        context: JoseContext = JoseContext.default)
                                       (encodePayload: (Boolean, Charset) => Either[Error, String])
  : F[Either[Error, JsonWebSignature]] =
    encodePayload(header.isBase64UrlEncodePayload, context.charset).fold(
      _.asLeft.pure[F],
      payload => sign[F](header, payload, key, context)
    )

  def sign[F[_]: Sync](header: JoseHeader, payload: String, key: Option[Key] = None,
                       context: JoseContext = JoseContext.default): F[Either[Error, JsonWebSignature]] =
    handleSignSignature[F, JsonWebSignature](header, payload, key, context)(
      (headerBase, signature) => JsonWebSignature(header, headerBase, payload, signature)
    )

  private[jws] def handleSignSignature[F[_]: Sync, S <: Signature](header: JoseHeader, payload: String,
                                                                   key: Option[Key] = None,
                                                                   context: JoseContext = JoseContext.default)
                                                                  (f: (Base64UrlNoPad, Base64UrlNoPad) => S)
  : F[Either[Error, S]] =
    val either =
      for
        headerBase <- encodeToBase(header, Base64UrlNoPad, context.charset)
        data <- toBytes(headerBase, payload, context.charset)
      yield
        handleSign[F](header.algorithm, key, data, context).map(_.map(
          signature => f(headerBase, Base64UrlNoPad.fromByteVector(signature))
        ))
    either.fold(_.asLeft.pure, identity)

  def handleSign[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                             context: JoseContext = JoseContext.default)
  : F[Either[Error, ByteVector]] =
    algorithm match
      case Some(`none`) | None => none.sign(key, data, context.doKeyValidation).pure[F]
      case Some(algo: SignaturePlatform) =>
        key match
          case Some(k) =>
            algo.signJws[F](k, data, context.doKeyValidation, context.useLegacyName, context.random,
              context.signatureProvider)
          case None => MissingKey.asLeft.pure[F]
      case Some(algo) => UnsupportedSignatureAlgorithm(algo).asLeft.pure[F]

  def handleVerify[F[_]: Sync](algorithm: Option[JsonWebAlgorithm], key: Option[Key], data: ByteVector,
                               signed: ByteVector, context: JoseContext = JoseContext.default)
  : F[Either[Error, Boolean]] =
    algorithm match
      case Some(`none`) | None => none.verify(key, data, signed, context.doKeyValidation).pure[F]
      case Some(algo: SignaturePlatform) =>
        key match
          case Some(k) =>
            algo.verifyJws[F](k, data, signed, context.doKeyValidation, context.useLegacyName,
              context.signatureProvider)
          case None => MissingKey.asLeft.pure[F]
      case Some(algo) => UnsupportedSignatureAlgorithm(algo).asLeft.pure[F]

  private[jws] def checkVerify[F[_]: Functor](eitherT: F[Either[Error, Boolean]]): F[Either[Error, Unit]] =
    eitherT.map(_.flatMap(isTrue(_, InvalidSignature)))
end JsonWebSignatureCompanion
