package com.peknight.jose.jws

import cats.data.Ior
import cats.{Id, Monad, Show}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.MissingField
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.error.Error
import com.peknight.jose.jws.JsonWebSignature.concat
import com.peknight.jose.jwx.{HeaderIor, JoseHeader}
import io.circe.{Json, JsonObject}
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}

trait Signature extends HeaderIor:
  def signature: Base64UrlNoPad
  def isBase64UrlEncodePayload: Either[Error, Boolean] =
    getUnprotectedHeader.map(_.isBase64UrlEncodePayload)

  def handleDecodePayload(payload: String, charset: Charset = StandardCharsets.UTF_8): Either[Error, ByteVector] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayload(payload, b64, charset))

  def handleDecodePayloadString(payload: String, charset: Charset = StandardCharsets.UTF_8): Either[Error, String] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayloadString(payload, b64, charset))

  def handleDecodePayloadJson[A](payload: String, charset: Charset = StandardCharsets.UTF_8)
                                (using Decoder[Id, Cursor[Json], A]): Either[Error, A] =
    isBase64UrlEncodePayload.flatMap(b64 => JsonWebSignature.decodePayloadJson(payload, b64, charset))

  def compact(payload: String): Either[Error, String] =
    getProtectedHeader.map(h => s"${concat(h, payload)}.${signature.value}")
  def detachedContentCompact: Either[Error, String] =
    getProtectedHeader.map(h => s"${h.value}..${signature.value}")
end Signature
object Signature:
  case class Signature private (headerIor: JoseHeader Ior Base64UrlNoPad, signature: Base64UrlNoPad)
    extends com.peknight.jose.jws.Signature
  object Signature:
    def apply(header: JoseHeader, signature: Base64UrlNoPad): Signature =
      Signature(Ior.Left(header), signature)

    def apply(`protected`: Base64UrlNoPad, signature: Base64UrlNoPad): Signature =
      Signature(Ior.Right(`protected`), signature)

    def apply(header: JoseHeader, `protected`: Base64UrlNoPad, signature: Base64UrlNoPad): Signature =
      Signature(Ior.Both(header, `protected`), signature)

    given codecSignature[F[_], S](using
      Monad[F], ObjectType[S], NullType[S], ArrayType[S], BooleanType[S], NumberType[S], StringType[S],
      Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S]
    ): Codec[F, S, Cursor[S], Signature] =
      Codec.forProduct[F, S, Signature, (Option[JoseHeader], Option[Base64UrlNoPad], Base64UrlNoPad)]
        (("header", "protected", "signature"))(jws => (jws.header, jws.`protected`, jws.signature)) {
          case ((Some(h), Some(p), signature)) => Right(apply(h, p, signature))
          case ((Some(h), None, signature)) => Right(apply(h, signature))
          case ((None, Some(p), signature)) => Right(apply(p, signature))
          case ((None, None, signature)) => Left(MissingField.label("header"))
        }
    given jsonCodecSignature[F[_]: Monad]: Codec[F, Json, Cursor[Json], Signature] = codecSignature[F, Json]
    given circeCodecSignature: io.circe.Codec[Signature] = codec[Signature]
  end Signature
end Signature