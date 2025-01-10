package com.peknight.jose.jws

import cats.data.Ior
import cats.parse.{Parser, Parser0}
import cats.syntax.either.*
import cats.{Id, Monad}
import com.peknight.cats.parse.ext.syntax.parser.flatMapE0
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.parser.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.MissingField
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwx.*
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}

/**
 * https://datatracker.ietf.org/doc/html/rfc7515
 * https://datatracker.ietf.org/doc/html/rfc7797#section-3
 */
case class JsonWebSignature private[jws] (
  headerIor: JoseHeader Ior Base64UrlNoPad,
  payload: String,
  signature: Base64UrlNoPad
) extends Signature with JsonWebStructure with JsonWebSignaturePlatform:
  def decodePayload(charset: Charset = StandardCharsets.UTF_8): Either[Error, ByteVector] =
    handleDecodePayload(payload, charset)
  def decodePayloadString(charset: Charset = StandardCharsets.UTF_8): Either[Error, String] =
    handleDecodePayloadString(payload, charset)
  def decodePayloadJson[A](charset: Charset = StandardCharsets.UTF_8)(using Decoder[Id, Cursor[Json], A])
  : Either[Error, A] =
    handleDecodePayloadJson(payload)
  def compact: Either[Error, String] = compact(payload)
  def getMergedHeader: Either[Error, JoseHeader] = getUnprotectedHeader
  def excludeHeader: Either[Error, JsonWebSignature] = 
    getProtectedHeader.map(`protected` => copy(headerIor = Ior.Right(`protected`)))
end JsonWebSignature

object JsonWebSignature extends JsonWebSignatureCompanion:
  def apply(header: JoseHeader, payload: String, signature: Base64UrlNoPad): JsonWebSignature =
    JsonWebSignature(Ior.Left(header), payload, signature)

  def apply(`protected`: Base64UrlNoPad, payload: String, signature: Base64UrlNoPad): JsonWebSignature =
    JsonWebSignature(Ior.Right(`protected`), payload, signature)

  def apply(header: JoseHeader, `protected`: Base64UrlNoPad, payload: String, signature: Base64UrlNoPad)
  : JsonWebSignature =
    JsonWebSignature(Ior.Both(header, `protected`), payload, signature)

  private val jsonWebSignatureParser: Parser0[JsonWebSignature] =
    (Base64UrlNoPad.baseParser ~ (Parser.char('.') *> Parser.charsWhile0(_ != '.')).rep(2)).flatMapE0 {
      case (headerBase, nel) =>
        val payload = nel.init.mkString(".")
        Base64UrlNoPad.baseParser.parseAll(nel.last).map(signature => JsonWebSignature(headerBase, payload, signature))
    }

  def parse(detachedContentCompact: String, payload: String): Either[Error, JsonWebSignature] =
    parse(detachedContentCompact.split("\\.\\.", 2).mkString(s".$payload.")).asError

  def parse(value: String): Either[Error, JsonWebSignature] = jsonWebSignatureParser.parseAll(value).asError

  given codecJsonWebSignature[F[_], S](using
    Monad[F], ObjectType[S], NullType[S], ArrayType[S], BooleanType[S], NumberType[S], StringType[S],
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

  def toBytes(header: Base64UrlNoPad, payload: String, charset: Charset = StandardCharsets.UTF_8)
  : Either[Error, ByteVector] =
    stringEncodeToBytes(concat(header, payload), charset)

  def encodePayload(payload: ByteVector, base64UrlEncodePayload: Boolean = true,
                    charset: Charset = StandardCharsets.UTF_8): Either[Error, String] =
    if base64UrlEncodePayload then Base64UrlNoPad.fromByteVector(payload).value.asRight
    else bytesDecodeToString(payload, charset)

  def encodePayloadString(payload: String, base64UrlEncodePayload: Boolean = true,
                          charset: Charset = StandardCharsets.UTF_8): Either[Error, String] =
    if base64UrlEncodePayload then stringEncodeToBase(payload, Base64UrlNoPad, charset).map(_.value)
    else payload.asRight

  def encodePayloadJson[A](payload: A, base64UrlEncodePayload: Boolean = true,
                           charset: Charset = StandardCharsets.UTF_8)
                          (using Encoder[Id, Json, A]): Either[Error, String] =
    encodePayloadString(encodeToJson(payload), base64UrlEncodePayload, charset)

  def decodePayload(payload: String, base64UrlEncodePayload: Boolean = true, charset: Charset = StandardCharsets.UTF_8)
  : Either[Error, ByteVector] =
    if base64UrlEncodePayload then Base64UrlNoPad.fromString(payload).flatMap(_.decode[Id])
    else stringEncodeToBytes(payload, charset)

  def decodePayloadString(payload: String, base64UrlEncodePayload: Boolean = true,
                          charset: Charset = StandardCharsets.UTF_8)
  : Either[Error, String] =
    if base64UrlEncodePayload then Base64UrlNoPad.fromString(payload).flatMap(base => baseDecodeToString(base, charset))
    else payload.asRight

  def decodePayloadJson[A](payload: String, base64UrlEncodePayload: Boolean = true,
                           charset: Charset = StandardCharsets.UTF_8)
                          (using Decoder[Id, Cursor[Json], A]): Either[Error, A] =
    decodePayloadString(payload, base64UrlEncodePayload, charset).flatMap(decode[Id, A])
end JsonWebSignature
