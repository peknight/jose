package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

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
        decodedPayload <- jws.decodePayloadString(StandardCharsets.US_ASCII).eLiftET[IO]
      yield
        parsedControlPayload == payload &&
          parsedDetachedContentCompactSerialization == detachedUnencoded &&
          parsedPayload == payload &&
          // for jose4j: the header just works out being the same based on (a little luck and) setting headers order
          // and how the JSON is produced
          // for me: not that lucky
          // detachedContentCompactSerialization == detachedUnencoded &&
          decodedPayload == payload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "UnencodedPayloadOption" should "succeed with RFC7797 examples with derect jws set header" in {
    // the key and payload are from https://tools.ietf.org/html/rfc7797#section-4
    val payload = "$.02"
    val jwkJson = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUu" +
      "TwjAzZr1Z9CAow\"}"
    // Test verifying the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
    val detachedUnencoded = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161Fw" +
      "XZC4YLPff6dmDY"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toKey[IO]())
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(HS256)).base64UrlEncodePayload(false), payload,
          Some(key), StandardCharsets.US_ASCII))
        detachedContentCompactSerialization <- jws.detachedContentCompact.eLiftET[IO]
        decodedPayload <- jws.decodePayloadString(StandardCharsets.US_ASCII).eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(detachedUnencoded, payload).asError.eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(key)))
        parsedPayload <- parsedJws.decodePayloadString(StandardCharsets.US_ASCII).eLiftET[IO]
        b64 <- parsedJws.isBase64UrlEncodePayload.eLiftET[IO]
      yield
        decodedPayload == payload && parsedPayload == payload && !b64
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "UnencodedPayloadOption" should "succeed with examples from draft even without direct support for the header" in {
    // a test of sorts to verify the examples from
    // http://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-09#section-4
    // at Mike's request
    val jwkJson = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUu" +
      "TwjAzZr1Z9CAow\"}"
    val payload = "$.02"
    val jwscsWithB64 = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"
    val jwscsWithoutB64andDetachedPayload = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FL" +
      "ueVuW1Z_vh161FwXZC4YLPff6dmDY"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toKey[IO]())
        payloadBytes <- ByteVector.encodeString(payload)(StandardCharsets.US_ASCII).asError.eLiftET[IO]
        payloadBase = Base64UrlNoPad.fromByteVector(payloadBytes)
        parsedJws <- JsonWebSignature.parse(jwscsWithB64).asError.eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(key)))
        parsedPayload <- parsedJws.decodePayloadUtf8.eLiftET[IO]
        jws <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(HS256)), payload, Some(key)))
        compact <- jws.compact.eLiftET[IO]
        detachedJws <- JsonWebSignature.parse(jwscsWithoutB64andDetachedPayload, payload).asError.eLiftET[IO]
        headerBase <- detachedJws.`protected`.toRight(OptionEmpty).eLiftET[IO]
        headerBytes <- headerBase.decode[Id].eLiftET[IO]
        headerJson <- headerBytes.decodeUtf8.asError.eLiftET[IO]
        signingInputString = JsonWebSignature.concat(headerBase, payload)
        signatureBytes <- detachedJws.signature.decode[Id].eLiftET[IO]
        securedInputBytes <- ByteVector.encodeString(signingInputString)(StandardCharsets.US_ASCII).asError.eLiftET[IO]
        flag <- EitherT(HS256.verifyJws[IO](key, securedInputBytes, signatureBytes))
        signed <- EitherT(HS256.signJws[IO](key, securedInputBytes))
        signedBase = Base64UrlNoPad.fromByteVector(signed)
      yield
        payloadBase.value == "JC4wMg" && parsedPayload == payload && compact == jwscsWithB64 &&
          headerJson == """{"alg":"HS256","b64":false,"crit":["b64"]}""" && flag &&
          signedBase.value == detachedJws.signature.value
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end UnencodedPayloadOptionFlatSpec
