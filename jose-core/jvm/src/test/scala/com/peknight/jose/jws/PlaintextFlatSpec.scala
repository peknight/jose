package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.none
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.mac.Hmac
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import javax.crypto.spec.SecretKeySpec

class PlaintextFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  private val jwsCompact: String = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9l" +
    "eGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  private val payload: String = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
  private val key: SecretKeySpec = Hmac.secretKeySpec(ByteVector(1, 2, 3, 4, 5, -3, 28, 123, -53))

  "Plaintext" should "succeed with example decode" in {
    val run =
      for
        jws <- JsonWebSignature.parse(jwsCompact).asError.eLiftET[IO]
        _ <- EitherT(jws.check[IO]())
        parsedPayload <- jws.decodePayloadUtf8.eLiftET[IO]
      yield
        parsedPayload == payload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "Plaintext" should "succeed with example encode" in {
    val run =
      for
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(none)), payload))
        compact <- jws.compact.eLiftET[IO]
      yield
        compact == jwsCompact
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "Plaintext" should "failed with sign with key no good" in {
    JsonWebSignature.signString[IO](JoseHeader(Some(none)), payload, Some(key)).asserting(either => assert(either.isLeft))
  }

  "Plaintext" should "failed with verify with key no good" in {
    val run =
      for
        jws <- JsonWebSignature.parse(jwsCompact).asError.eLiftET[IO]
        _ <- EitherT(jws.check[IO](Some(key)).map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "Plaintext" should "succeed with a decode" in {
    val cs = "eyJhbGciOiJub25lIn0.eyJhdXRoX3RpbWUiOjEzMzk2MTMyNDgsImV4cCI6MTMzOTYxMzU0OCwiaXNzIjoiaHR0cHM6XC9cL2V4YW" +
      "1wbGUuY29tIiwiYXVkIjoiYSIsImp0aSI6ImpJQThxYTM1QXJvVjZpUDJxNHdSQWwiLCJ1c2VyX2lkIjoiam9obiIsImlhdCI6MTMzOTYxMzI" +
      "0OCwiYWNyIjozfQ."
    val run =
      for
        jws <- JsonWebSignature.parse(cs).asError.eLiftET[IO]
        _ <- EitherT(jws.check[IO]())
        _ <- jws.decodePayloadUtf8.eLiftET[IO]
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

end PlaintextFlatSpec
