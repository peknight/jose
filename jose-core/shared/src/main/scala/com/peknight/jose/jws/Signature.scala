package com.peknight.jose.jws

import cats.{Id, Monad}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.{DecodingFailure, MissingField}
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.jose.error.jws.JsonWebSignatureError
import com.peknight.jose.jws.JsonWebSignature.{concat, fromBase, toBase}
import com.peknight.jose.jwx.JoseHeader
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

trait Signature:
  def headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]
  def signature: Base64UrlNoPad
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

  def decodePayload(payload: String): Either[DecodingFailure, ByteVector] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayload(payload, b64))

  def decodePayloadJson[T](payload: String)(using Decoder[Id, Cursor[Json], T]): Either[DecodingFailure, T] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayloadJson(payload, b64))

  def compact(payload: String): Either[JsonWebSignatureError, String] =
    getProtectedHeader.map(h => s"${concat(h, payload)}.${signature.value}")
end Signature
object Signature:
  case class Signature private (
    headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)], signature: Base64UrlNoPad
  ) extends com.peknight.jose.jws.Signature
  object Signature:
    def apply(header: JoseHeader, signature: Base64UrlNoPad): Signature =
      Signature(Left(Left(header)), signature)

    def apply(`protected`: Base64UrlNoPad, signature: Base64UrlNoPad): Signature =
      Signature(Left(Right(`protected`)), signature)

    def apply(header: JoseHeader, `protected`: Base64UrlNoPad, signature: Base64UrlNoPad): Signature =
      Signature(Right((header, `protected`)), signature)

    given codecSignature[F[_], S](using
     Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
     Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
    ): Codec[F, S, Cursor[S], Signature] =
      Codec.forProduct[F, S, Signature, (Option[JoseHeader], Option[Base64UrlNoPad], Base64UrlNoPad)]
        (("header", "protected", "signature"))(jws => (jws.header, jws.`protected`, jws.signature)) {
          case ((Some(h), Some(p), signature)) => Right(apply(h, p, signature))
          case ((Some(h), None, signature)) => Right(apply(h, signature))
          case ((None, Some(p), signature)) => Right(apply(p, signature))
          case ((None, None, signature)) => Left(MissingField.label("header"))
        }
  end Signature
end Signature