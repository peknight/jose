package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.codec.error.WrongClassTag
import com.peknight.jose.JoseHeader
import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.jose.jwt.JsonWebTokenClaims
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class JsonWebSignatureFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebSignature" should "succeed" in {
    val header = JoseHeader.jwtHeader(HS256)
    val jwtClaims = JsonWebTokenClaims(
      issuer = Some("joe"),
      expirationTime = Some(Instant.ofEpochSecond(1300819380)),
      ext = Some(JsonObject("http://example.com/is_root" -> Json.True))
    )
    val jwkJsonString =
      s"""
         |{
         |  "kty":"oct",
         |  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
         |}
      """.stripMargin
    val eitherT =
      for
        jwk <- EitherT(decode[IO, JsonWebKey](jwkJsonString))
        _ = println(jwk)
        key <- jwk match
          case jwk: OctetSequenceJsonWebKey => EitherT(jwk.toKey[IO])
          case _ => EitherT(IO(Left(WrongClassTag[OctetSequenceJsonWebKey])))
        signature <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](header, jwtClaims, Some(key)))
        _ = println(signature)
        result <- EitherT(signature.verify[IO](Some(key)))
        _ = println(result)
      yield true
    eitherT.value.map(_.getOrElse(false)).asserting(assert)
  }
end JsonWebSignatureFlatSpec
