package com.peknight.jose.jws

import cats.Id
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.syntax.encoder.asS
import com.peknight.jose.JoseHeader
import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwt.JsonWebTokenClaims
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AnyFlatSpec
import scodec.bits.ByteVector

import java.time.Instant

class JsonWebSignatureFlatSpec extends AnyFlatSpec:
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
    val jwk = decode[Id, JsonWebKey](jwkJsonString)
    println(s"jwk: $jwk")
    val origin = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

    assert(true)
  }
end JsonWebSignatureFlatSpec
