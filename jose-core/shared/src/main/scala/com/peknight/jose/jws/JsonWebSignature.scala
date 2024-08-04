package com.peknight.jose.jws

import cats.Id
import cats.parse.{Parser, Parser0}
import com.peknight.codec.base.Base64Url
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jws.JsonWebSignature.Raw
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.CharacterCodingException

case class JsonWebSignature(header: JsonWebSignatureHeader, payload: ByteVector, signature: ByteVector):
  def raw: Either[CharacterCodingException, Raw] =
    ByteVector
      .encodeUtf8(JsonWebSignatureHeader.codecJsonWebSignatureHeader[Id, Json]
        .encode(header)
        .deepDropNullValues
        .noSpaces)
      .map(headerBytes => Raw(
        Base64Url.unsafeFromString(headerBytes.toBase64Url),
        Base64Url.unsafeFromString(payload.toBase64Url),
        Base64Url.unsafeFromString(signature.toBase64Url))
      )
  def mkString: Either[CharacterCodingException, String] = raw.map(_.mkString)
end JsonWebSignature

object JsonWebSignature:
  case class Raw(header: Base64Url, payload: Base64Url, signature: Base64Url):
    def mkString: String = s"${header.value}.${payload.value}.${signature.value}"
  end Raw

  val jsonWebSignatureRawParser: Parser0[Raw] =
    ((Base64Url.baseParser <* Parser.char('.')) ~ (Base64Url.baseParser <* Parser.char('.')) ~ Base64Url.baseParser)
      .map { case ((headerBase64, payloadBase64), signatureBase64) =>
        Raw(headerBase64, payloadBase64, signatureBase64)
      }

  val jsonWebSignatureParser: Parser0[JsonWebSignature] =
    jsonWebSignatureRawParser.flatMap { raw =>
      val result =
        for
          headerBytes <- raw.header.decode[Id]
          headerJsonString <- headerBytes.decodeUtf8.left.map(DecodingFailure.apply)
          header <- decode[Id, JsonWebSignatureHeader](headerJsonString)
          payload <- raw.payload.decode[Id]
          signature <- raw.signature.decode[Id]
        yield JsonWebSignature(header, payload, signature)
      result match
        case Left(error) => Parser.failWith[JsonWebSignature](error.message)
        case Right(value) => Parser.pure(value)
    }
end JsonWebSignature
