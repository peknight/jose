package com.peknight.jose.jws

import cats.parse.{Parser, Parser0}
import cats.syntax.either.*
import cats.{Id, Monad}
import com.peknight.codec.base.{Base, Base64UrlNoPad, BaseAlphabetPlatform}
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.{DecodingFailure, MissingField}
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.syntax.encoder.asS
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.jose.JoseHeader
import com.peknight.jose.error.jws.{CharacterCodingError, JsonWebSignatureError}
import com.peknight.jose.jws.JsonWebSignature.{concat, fromBase, toBase}
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

import java.nio.charset.CharacterCodingException
import scala.reflect.ClassTag

case class JsonWebSignature private (
  headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)],
  payload: Base64UrlNoPad,
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

  def compact: Either[JsonWebSignatureError, String] =
    getProtectedHeader.map(h => s"${concat(h, payload)}.${signature.value}")
end JsonWebSignature

object JsonWebSignature extends JsonWebSignatureCompanion:
  def apply(header: JoseHeader, payload: Base64UrlNoPad, signature: Base64UrlNoPad): JsonWebSignature =
    JsonWebSignature(Left(Left(header)), payload, signature)

  def apply(`protected`: Base64UrlNoPad, payload: Base64UrlNoPad, signature: Base64UrlNoPad): JsonWebSignature =
    JsonWebSignature(Left(Right(`protected`)), payload, signature)

  def apply(header: JoseHeader, `protected`: Base64UrlNoPad, payload: Base64UrlNoPad, signature: Base64UrlNoPad)
  : JsonWebSignature =
    JsonWebSignature(Right((header, `protected`)), payload, signature)

  val jsonWebSignatureParser: Parser0[JsonWebSignature] =
    ((Base64UrlNoPad.baseParser <* Parser.char('.')) ~ (Base64UrlNoPad.baseParser <* Parser.char('.')) ~ Base64UrlNoPad.baseParser)
      .map { case ((p, payload), signature) =>
        JsonWebSignature(Left(Right(p)), payload, signature)
      }

  given codecJsonWebSignature[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebSignature] =
    Codec.forProduct[F, S, JsonWebSignature, (Option[JoseHeader], Option[Base64UrlNoPad], Base64UrlNoPad, Base64UrlNoPad)]
      (("header", "protected", "payload", "signature"))(jws => (jws.header, jws.`protected`, jws.payload, jws.signature)) {
        case ((Some(h), Some(p), payload, signature)) => Right(apply(h, p, payload, signature))
        case ((Some(h), None, payload, signature)) => Right(apply(h, payload, signature))
        case ((None, Some(p), payload, signature)) => Right(apply(p, payload, signature))
        case ((None, None, payload, signature)) => Left(MissingField.label("header"))
      }

  given jsonCodecJsonWebSignature[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebSignature] =
    codecJsonWebSignature[F, Json]

  given circeCodecJsonWebSignature: io.circe.Codec[JsonWebSignature] = codec[JsonWebSignature]

  def concat(header: Base64UrlNoPad, payload: Base64UrlNoPad): String = s"${header.value}.${payload.value}"

  def toBytes(header: Base64UrlNoPad, payload: Base64UrlNoPad): Either[JsonWebSignatureError, ByteVector] =
    ByteVector.encodeUtf8(concat(header, payload)).left.map(CharacterCodingError.apply)

  def toBytes[T](t: T)(using Encoder[Id, Json, T]): Either[JsonWebSignatureError, ByteVector] =
    ByteVector.encodeUtf8(t.asS[Id, Json].deepDropNullValues.noSpaces).left.map(CharacterCodingError.apply)

  def toBase[T, B <: Base : ClassTag](t: T, base: BaseAlphabetPlatform[?, B])(using Encoder[Id, Json, T])
  : Either[JsonWebSignatureError, B] =
    toBytes[T](t).map(base.fromByteVector)

  def fromBase[T](b: Base)(using Decoder[Id, Cursor[Json], T]): Either[DecodingFailure, T] =
    for
      bytes <- b.decode[Id]
      jsonString <- bytes.decodeUtf8.left.map(DecodingFailure.apply)
      t <- decode[Id, T](jsonString)
    yield t
end JsonWebSignature
