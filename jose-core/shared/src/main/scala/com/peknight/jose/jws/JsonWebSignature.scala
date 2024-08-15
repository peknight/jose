package com.peknight.jose.jws

import cats.parse.{Parser, Parser0}
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.{Id, Monad}
import com.peknight.cats.parse.ext.syntax.parser.flatMapE0
import com.peknight.codec.base.{Base, Base64UrlNoPad, BaseAlphabetPlatform}
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.{DecodingFailure, MissingField}
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.syntax.encoder.asS
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.jose.error.jws.{CharacterCodingError, JsonWebSignatureError}
import com.peknight.jose.jws.JsonWebSignature.{concat, fromBase, toBase}
import com.peknight.jose.jwx.JoseHeader
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

import java.nio.charset.CharacterCodingException
import scala.reflect.ClassTag

/**
 * https://datatracker.ietf.org/doc/html/rfc7515
 * https://datatracker.ietf.org/doc/html/rfc7797#section-3
 */
case class JsonWebSignature private (
  headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)],
  payload: String,
  signature: Base64UrlNoPad
) extends JsonWebSignaturePlatform:
  def header: Option[JoseHeader] =
    headerEither match
      case Left(Left(h)) => Some(h)
      case Right((h, _)) => Some(h)
      case _ => None

  def `protected`: Option[Base64UrlNoPad] =
    headerEither match
      case Left(Right(p)) => Some(p)
      case Right((_, p)) => Some(p)
      case _ => None

  def getUnprotectedHeader: Either[DecodingFailure, JoseHeader] =
    headerEither match
      case Left(Left(h)) => Right(h)
      case Right((h, _)) => Right(h)
      case Left(Right(p)) => fromBase[JoseHeader](p)

  def getProtectedHeader: Either[JsonWebSignatureError, Base64UrlNoPad] =
    headerEither match
      case Left(Right(p)) => Right(p)
      case Right((_, p)) => Right(p)
      case Left(Left(h)) => toBase(h, Base64UrlNoPad)

  def isBase64UrlEncodePayload: Either[DecodingFailure, Boolean] =
    getUnprotectedHeader.map(_.isBase64UrlEncodePayload)

  def decodePayload: Either[DecodingFailure, ByteVector] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayload(payload, b64))

  def decodePayloadJson[T](using Decoder[Id, Cursor[Json], T]): Either[DecodingFailure, T] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayloadJson(payload, b64))

  def compact: Either[JsonWebSignatureError, String] =
    getProtectedHeader.map(h => s"${concat(h, payload)}.${signature.value}")
end JsonWebSignature

object JsonWebSignature extends JsonWebSignatureCompanion:
  def apply(header: JoseHeader, payload: String, signature: Base64UrlNoPad): JsonWebSignature =
    JsonWebSignature(Left(Left(header)), payload, signature)

  def apply(`protected`: Base64UrlNoPad, payload: String, signature: Base64UrlNoPad): JsonWebSignature =
    JsonWebSignature(Left(Right(`protected`)), payload, signature)

  def apply(header: JoseHeader, `protected`: Base64UrlNoPad, payload: String, signature: Base64UrlNoPad)
  : JsonWebSignature =
    JsonWebSignature(Right((header, `protected`)), payload, signature)

  val jsonWebSignatureParser: Parser0[JsonWebSignature] =
    (Base64UrlNoPad.baseParser ~ (Parser.char('.') *> Parser.charsWhile0(_ != '.')).rep(2)).flatMapE0 {
      case (headerBase, nel) =>
        val payload = nel.init.mkString(".")
        Base64UrlNoPad.baseParser.parseAll(nel.last).map(signature => JsonWebSignature(headerBase, payload, signature))
    }

  given codecJsonWebSignature[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebSignature] =
    Codec.forProduct[F, S, JsonWebSignature, (Option[JoseHeader], Option[Base64UrlNoPad], String, Base64UrlNoPad)]
      (("header", "protected", "payload", "signature"))(jws => (jws.header, jws.`protected`, jws.payload, jws.signature)) {
        case ((Some(h), Some(p), payload, signature)) => Right(apply(h, p, payload, signature))
        case ((Some(h), None, payload, signature)) => Right(apply(h, payload, signature))
        case ((None, Some(p), payload, signature)) => Right(apply(p, payload, signature))
        case ((None, None, payload, signature)) => Left(MissingField.label("header"))
      }

  given jsonCodecJsonWebSignature[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebSignature] =
    codecJsonWebSignature[F, Json]

  given circeCodecJsonWebSignature: io.circe.Codec[JsonWebSignature] = codec[JsonWebSignature]

  def concat(header: Base64UrlNoPad, payload: String): String = s"${header.value}.$payload"

  def toBytes(value: String): Either[JsonWebSignatureError, ByteVector] =
    ByteVector.encodeUtf8(value).left.map(CharacterCodingError.apply)

  def toBytes(header: Base64UrlNoPad, payload: String): Either[JsonWebSignatureError, ByteVector] =
    toBytes(concat(header, payload))

  def toJsonBytes[T](t: T)(using Encoder[Id, Json, T]): Either[JsonWebSignatureError, ByteVector] =
    toBytes(t.asS[Id, Json].deepDropNullValues.noSpaces)

  def toBase[T, B <: Base : ClassTag](t: T, base: BaseAlphabetPlatform[?, B])(using Encoder[Id, Json, T])
  : Either[JsonWebSignatureError, B] =
    toJsonBytes[T](t).map(base.fromByteVector)

  def fromBase[T](b: Base)(using Decoder[Id, Cursor[Json], T]): Either[DecodingFailure, T] =
    for
      bytes <- b.decode[Id]
      jsonString <- bytes.decodeUtf8.left.map(DecodingFailure.apply)
      t <- decode[Id, T](jsonString)
    yield t

  def encodePayload(payload: ByteVector, base64UrlEncodePayload: Boolean): Either[JsonWebSignatureError, String] =
    if base64UrlEncodePayload then Base64UrlNoPad.fromByteVector(payload).value.asRight
    else payload.decodeUtf8.left.map(CharacterCodingError.apply)

  def encodePayloadJson[T](payload: T, base64UrlEncodePayload: Boolean)(using Encoder[Id, Json, T])
  : Either[JsonWebSignatureError, String] =
    if base64UrlEncodePayload then toBase(payload, Base64UrlNoPad).map(_.value)
    else payload.asS[Id, Json].deepDropNullValues.noSpaces.asRight

  def decodePayload(payload: String, base64UrlEncodePayload: Boolean): Either[DecodingFailure, ByteVector] =
    (if base64UrlEncodePayload then Base64UrlNoPad.fromString(payload).flatMap(_.decode[Id]) else toBytes(payload))
      .left.map(DecodingFailure.apply)

  def decodePayloadJson[T](payload: String, base64UrlEncodePayload: Boolean)(using Decoder[Id, Cursor[Json], T])
  : Either[DecodingFailure, T] =
    val jsonEither =
      if base64UrlEncodePayload then Base64UrlNoPad.fromString(payload).flatMap(_.decode[Id]).flatMap(_.decodeUtf8)
      else payload.asRight
    jsonEither match
      case Left(error) => DecodingFailure(error).asLeft
      case Right(json) => decode[Id, T](json)
end JsonWebSignature
