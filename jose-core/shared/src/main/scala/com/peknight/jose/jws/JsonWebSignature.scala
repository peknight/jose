package com.peknight.jose.jws

import cats.parse.{Parser, Parser0}
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.{Id, Monad}
import com.peknight.cats.parse.ext.syntax.parser.flatMapE0
import com.peknight.codec.base.{Base, Base64UrlNoPad, BaseAlphabetPlatform}
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.parser.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.{DecodingFailure, MissingField}
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.syntax.encoder.asS
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.jws.{CharacterCodingError, JsonWebSignatureError}
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
) extends Signature with JsonWebSignaturePlatform:
  def decodePayload: Either[Error, ByteVector] = decodePayload(payload)
  def decodePayloadJson[T](using Decoder[Id, Cursor[Json], T]): Either[Error, T] = decodePayloadJson(payload)
  def compact: Either[Error, String] = compact(payload)
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

  def toBytes(value: String): Either[Error, ByteVector] = ByteVector.encodeUtf8(value).asError

  def toBytes(header: Base64UrlNoPad, payload: String): Either[Error, ByteVector] = toBytes(concat(header, payload))

  def toJsonBytes[T](t: T)(using Encoder[Id, Json, T]): Either[Error, ByteVector] =
    toBytes(t.asS[Id, Json].deepDropNullValues.noSpaces)

  def toBase[T, B <: Base : ClassTag](t: T, base: BaseAlphabetPlatform[?, B])(using Encoder[Id, Json, T])
  : Either[Error, B] =
    toJsonBytes[T](t).map(base.fromByteVector)

  def fromBase[T](b: Base)(using Decoder[Id, Cursor[Json], T]): Either[Error, T] =
    for
      bytes <- b.decode[Id]
      jsonString <- bytes.decodeUtf8.asError
      t <- decode[Id, T](jsonString)
    yield t

  def encodePayload(payload: ByteVector, base64UrlEncodePayload: Boolean): Either[Error, String] =
    if base64UrlEncodePayload then Base64UrlNoPad.fromByteVector(payload).value.asRight
    else payload.decodeUtf8.asError

  def encodePayloadJson[T](payload: T, base64UrlEncodePayload: Boolean)(using Encoder[Id, Json, T])
  : Either[Error, String] =
    if base64UrlEncodePayload then toBase(payload, Base64UrlNoPad).map(_.value)
    else payload.asS[Id, Json].deepDropNullValues.noSpaces.asRight

  def decodePayload(payload: String, base64UrlEncodePayload: Boolean): Either[Error, ByteVector] =
    if base64UrlEncodePayload then Base64UrlNoPad.fromString(payload).flatMap(_.decode[Id]) else toBytes(payload)

  def decodePayloadJson[T](payload: String, base64UrlEncodePayload: Boolean)(using Decoder[Id, Cursor[Json], T])
  : Either[Error, T] =
    if base64UrlEncodePayload then
      for
        base64 <- Base64UrlNoPad.fromString(payload)
        bytes <- base64.decode[Id]
        json <- bytes.decodeUtf8.asError
        res <- decode[Id, T](json)
      yield res
    else decode[Id, T](payload)
end JsonWebSignature
