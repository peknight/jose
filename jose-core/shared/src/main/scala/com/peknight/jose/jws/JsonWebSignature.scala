package com.peknight.jose.jws

import cats.parse.{Parser, Parser0}
import cats.{Id, Monad}
import com.peknight.codec.base.Base64Url
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.{DecodingFailure, MissingField}
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.syntax.encoder.asS
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.jose.error.{CharacterCodingError, JsonWebSignatureEncodingError}
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

import java.nio.charset.CharacterCodingException

case class JsonWebSignature private (
  headerEither: Either[Either[JsonWebSignatureHeader, Base64Url], (JsonWebSignatureHeader, Base64Url)],
  payload: Base64Url,
  signature: Base64Url
):
  def header: Option[JsonWebSignatureHeader] =
    headerEither match
      case Left(Left(h)) => Some(h)
      case Right((h, _)) => Some(h)
      case _ => None

  def `protected`: Option[Base64Url] =
    headerEither match
      case Left(Right(p)) => Some(p)
      case Right((_, p)) => Some(p)
      case _ => None

  def getUnprotectedHeader: Either[DecodingFailure, JsonWebSignatureHeader] =
    headerEither match
      case Left(Left(h)) => Right(h)
      case Right((h, _)) => Right(h)
      case Left(Right(p)) =>
        for
          headerBytes <- p.decode[Id]
          headerJsonString <- headerBytes.decodeUtf8.left.map(DecodingFailure.apply)
          h <- decode[Id, JsonWebSignatureHeader](headerJsonString)
        yield h

  def getProtectedHeader: Either[JsonWebSignatureEncodingError, Base64Url] =
    headerEither match
      case Left(Right(p)) => Right(p)
      case Right((_, p)) => Right(p)
      case Left(Left(h)) =>
        ByteVector.encodeUtf8(h.asS[Id, Json].deepDropNullValues.noSpaces) match
          case Right(bytes) => Right(Base64Url.fromByteVector(bytes))
          case Left(e) => Left(CharacterCodingError(e))

  def compact: Either[JsonWebSignatureEncodingError, String] =
    getProtectedHeader.map(h => s"${h.value}.${payload.value}.${signature.value}")
end JsonWebSignature

object JsonWebSignature:
  def apply(header: JsonWebSignatureHeader, payload: Base64Url, signature: Base64Url): JsonWebSignature =
    JsonWebSignature(Left(Left(header)), payload, signature)

  def apply(`protected`: Base64Url, payload: Base64Url, signature: Base64Url): JsonWebSignature =
    JsonWebSignature(Left(Right(`protected`)), payload, signature)

  def apply(header: JsonWebSignatureHeader, `protected`: Base64Url, payload: Base64Url, signature: Base64Url)
  : JsonWebSignature =
    JsonWebSignature(Right((header, `protected`)), payload, signature)

  val jsonWebSignatureParser: Parser0[JsonWebSignature] =
    ((Base64Url.baseParser <* Parser.char('.')) ~ (Base64Url.baseParser <* Parser.char('.')) ~ Base64Url.baseParser)
      .map { case ((p, payload), signature) =>
        JsonWebSignature(Left(Right(p)), payload, signature)
      }

  given codecJsonWebSignature[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebSignature] =
    Codec.forProduct[F, S, JsonWebSignature, (Option[JsonWebSignatureHeader], Option[Base64Url], Base64Url, Base64Url)]
      (("header", "protected", "payload", "signature"))(jws => (jws.header, jws.`protected`, jws.payload, jws.signature)) {
        case ((Some(h), Some(p), payload, signature)) => Right(apply(h, p, payload, signature))
        case ((Some(h), None, payload, signature)) => Right(apply(h, payload, signature))
        case ((None, Some(p), payload, signature)) => Right(apply(p, payload, signature))
        case ((None, None, payload, signature)) => Left(MissingField.label("header"))
      }

  given jsonCodecJsonWebSignature[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebSignature] =
    codecJsonWebSignature[F, Json]

  given circeCodecJsonWebSignature: io.circe.Codec[JsonWebSignature] = codec[JsonWebSignature]

end JsonWebSignature
