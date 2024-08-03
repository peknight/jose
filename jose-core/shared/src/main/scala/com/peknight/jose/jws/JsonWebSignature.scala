package com.peknight.jose.jws

import cats.Id
import cats.parse.{Parser, Parser0}
import com.peknight.codec.base.Base64Url
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.error.DecodingFailure
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.CharacterCodingException

case class JsonWebSignature(header: JsonWebSignatureHeader, payload: ByteVector, signature: ByteVector):
  def mkString: Either[CharacterCodingException, String] =
    ByteVector.encodeUtf8(JsonWebSignatureHeader.codecJsonWebSignatureHeader[Id, Json].encode(header).deepDropNullValues.noSpaces)
      .map(headerBytes => s"${headerBytes.toBase64Url}.${payload.toBase64Url}.${signature.toBase64Url}")
end JsonWebSignature

object JsonWebSignature:
  val jsonWebSignatureParser: Parser0[JsonWebSignature] =
    ((Base64Url.baseParser <* Parser.char('.')) ~ (Base64Url.baseParser <* Parser.char('.')) ~ Base64Url.baseParser)
      .flatMap { case ((headerBase64, payloadBase64), signatureBase64) =>
        val result =
          for
            headerBytes <- headerBase64.decode[Id]
            headerJsonString <- headerBytes.decodeUtf8.left.map(DecodingFailure.apply)
            header <- decode[Id, JsonWebSignatureHeader](headerJsonString)
            payload <- payloadBase64.decode[Id]
            signature <- signatureBase64.decode[Id]
          yield JsonWebSignature(header, payload, signature)
        result match
          case Left(error) => Parser.failWith[JsonWebSignature](error.message)
          case Right(value) => Parser.pure(value)
      }
end JsonWebSignature
