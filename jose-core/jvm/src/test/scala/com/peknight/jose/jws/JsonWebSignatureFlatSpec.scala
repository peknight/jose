package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.either.*
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.error.{DecodingFailure, WrongClassTag}
import com.peknight.codec.syntax.encoder.asS
import com.peknight.jose.JoseHeader
import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.jose.jwt.JsonWebTokenClaims
import com.peknight.security.crypto.Mac
import com.peknight.security.mac.HmacSHA256
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import java.time.Instant

class JsonWebSignatureFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebSignature" should "succeed" in {
    val header = JoseHeader.jwtHeader(HS256)
    println(s"header: $header")
    val headerJsonString = header.asS[Id, Json].deepDropNullValues.noSpaces
    println(s"headerJsonString: $headerJsonString")
    val headerBase64 = ByteVector.encodeUtf8(headerJsonString).map(Base64UrlNoPad.fromByteVector)
    println(s"headerBase64: $headerBase64")
    val jwtClaims = JsonWebTokenClaims(
      issuer = Some("joe"),
      expirationTime = Some(Instant.ofEpochSecond(1300819380)),
      ext = Some(JsonObject("http://example.com/is_root" -> Json.True))
    )
    println(s"jwtClaims: $jwtClaims")
    val jwtClaimsJsonString = jwtClaims.asS[Id, Json].deepDropNullValues.noSpaces
    println(s"jwtClaimsJsonString: $jwtClaimsJsonString")
    val jwtClaimsBase64 = ByteVector.encodeUtf8(jwtClaimsJsonString).map(Base64UrlNoPad.fromByteVector)
    println(s"jwtClaimsBase64: $jwtClaimsBase64")
    val jwkJsonString =
      s"""
         |{
         |  "kty":"oct",
         |  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
         |}
      """.stripMargin
    val origin = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    val jwsRawString = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    println(JsonWebSignature.jsonWebSignatureParser.parseAll(jwsRawString))
    val eitherT =
      for
        jwk <- EitherT(decode[IO, JsonWebKey](jwkJsonString))
        key <- jwk match
          case jwk: OctetSequenceJsonWebKey => EitherT(jwk.toKey[IO])
          case _ => EitherT(IO(Left(WrongClassTag[OctetSequenceJsonWebKey])))
        input <- EitherT(IO(ByteVector.encodeUtf8(origin).left.map(DecodingFailure.apply)))
        result <- EitherT(Mac.mac[IO](HmacSHA256, key, input).map(_.asRight))
        _ = println(result.toBase64UrlNoPad)
      yield true
    eitherT.value.map(_.getOrElse(false)).asserting(assert)
  }
end JsonWebSignatureFlatSpec
