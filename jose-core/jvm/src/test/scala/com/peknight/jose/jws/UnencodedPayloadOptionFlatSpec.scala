package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec

import java.nio.charset.StandardCharsets

class UnencodedPayloadOptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "UnencodedPayloadOption" should "succeed with RFC7797 examples" in {
    // the key and payload are from https://tools.ietf.org/html/rfc7797#section-4
    val payload = "$.02"
    val jwkJson = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUu" +
      "TwjAzZr1Z9CAow\"}"
    // Test the "control" JWS from https://tools.ietf.org/html/rfc7797#section-4.1
    val controlCompactSerialization = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"
    // Test verifying the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
    val detachedUnencoded = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161Fw" +
      "XZC4YLPff6dmDY"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toKey[IO]())
        controlJws <- JsonWebSignature.parse(controlCompactSerialization).asError.eLiftET[IO]
        _ <- EitherT(controlJws.check[IO](Some(key)))
        parsedControlPayload <- controlJws.decodePayloadString(StandardCharsets.US_ASCII).eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(detachedUnencoded, payload).asError.eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(key)))
        parsedDetachedContentCompactSerialization <- parsedJws.detachedContentCompact.eLiftET[IO]
        parsedPayload <- parsedJws.decodePayloadString(StandardCharsets.US_ASCII).eLiftET[IO]
        // reconstruct the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(HS256)).base64UrlEncodePayload(false), payload,
          Some(key), StandardCharsets.US_ASCII))
        detachedContentCompactSerialization <- jws.detachedContentCompact.eLiftET[IO]
        nextPayload <- jws.decodePayloadString(StandardCharsets.US_ASCII).eLiftET[IO]
      yield
        parsedControlPayload == payload &&
          parsedDetachedContentCompactSerialization == detachedUnencoded &&
          parsedPayload == payload &&
          // for jose4j: the header just works out being the same based on (a little luck and) setting headers order and how the JSON is produced
          // for me: not that lucky
          // detachedContentCompactSerialization == detachedUnencoded &&
          nextPayload == payload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end UnencodedPayloadOptionFlatSpec
