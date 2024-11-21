package com.peknight.jose.jws

import cats.{Id, Monad}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.MissingField
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.error.Error
import com.peknight.jose.jws.JsonWebSignature.concat
import com.peknight.jose.jwx.{HeaderEither, JoseHeader}
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

trait Signature extends HeaderEither:
  def signature: Base64UrlNoPad
  def isBase64UrlEncodePayload: Either[Error, Boolean] =
    getUnprotectedHeader.map(_.isBase64UrlEncodePayload)

  def decodePayload(payload: String): Either[Error, ByteVector] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayload(payload, b64))

  def decodePayloadJson[T](payload: String)(using Decoder[Id, Cursor[Json], T]): Either[Error, T] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayloadJson(payload, b64))

  def compact(payload: String): Either[Error, String] =
    getProtectedHeader.map(h => s"${concat(h, payload)}.${signature.value}")
  def detachedContentCompact: Either[Error, String] =
    getProtectedHeader.map(h => s"${h.value}..${signature.value}")
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
     Monad[F], ObjectType[S], NullType[S], ArrayType[S], BooleanType[S], NumberType[S], StringType[S],
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