package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.ecc.`P-256`
import com.peknight.jose.jwa.signature.ES256
import com.peknight.jose.jwk.{d256, x256, y256}
import com.peknight.jose.jwx.{JoseHeader, toBytes}
import com.peknight.security.syntax.ecParameterSpec.{privateKey, publicKey}
import org.scalatest.flatspec.AsyncFlatSpec

class CriticalHeaderFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  "CriticalHeader" should "succeed with unknown critical header" in {
    val headerName = "urn:example.com:nope"
    List(
      "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsidXJuOmV4YW1wbGUuY29tOm5vcGUiXX0.aG93IGNyaXRpY2FsIHJlYWxseT8.F-xgvRuuaqawpLAiq" +
        "6ArALlPB0Ay5_EU0YSPtw4U9teq82Gv1GyNzpO51V-u35p_oCe9dT-h0HxeznIg-uMxpQ",
      "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsidXJuOmV4YW1wbGUuY29tOm5vcGUiXSwidXJuOmV4YW1wbGUuY29tOm5vcGUiOiJodWgifQ.aG93IG" +
        "NyaXRpY2FsIHJlYWxseT8.xZvf_WCSZY2-oMvpTbHALCGgOchR8ryrV_84Q5toM8KECtm9PCEuORoMKHmCFx-UTOI1QNt28H51GV9MB4c6BQ")
      .traverse { cs =>
        for
          jws <- JsonWebSignature.parse(cs).asError.eLiftET[IO]
          publicKey <- EitherT(`P-256`.ecParameterSpec.publicKey[IO](x256, y256).asError)
          _ <- EitherT(jws.verify[IO](Some(publicKey)).map(_.swap.asError))
          _ <- EitherT(jws.check[IO](Some(publicKey), List(headerName)))
          payloadBytes <- jws.decodePayload.eLiftET[IO]
          payload <- payloadBytes.decodeUtf8.asError.eLiftET[IO]
        yield
          payload == "how critical really?"
      }
      .map(_.forall(identity))
      .value
      .asserting(value => assert(value.getOrElse(false)))
  }

  "CriticalHeader" should "succeed with jws appendix E" in {
    // http://tools.ietf.org/html/rfc7515#appendix-E
    val cs = "eyJhbGciOiJub25lIiwNCiAiY3JpdCI6WyJodHRwOi8vZXhhbXBsZS5jb20vVU5ERUZJTkVEIl0sDQogImh0dHA6Ly9leGFtcGxlLm" +
      "NvbS9VTkRFRklORUQiOnRydWUNCn0.RkFJTA."
    val run =
      for
        jws <- JsonWebSignature.parse(cs).asError.eLiftET[IO]
        _ <- EitherT(jws.verify[IO]().map(_.swap.asError))
        // -> in the actual encoded example even thought the text says http://example.invalid/UNDEFINED
        _ <- EitherT(jws.check[IO](None, List("http://example.com/UNDEFINED")))
        payloadBytes <- jws.decodePayload.eLiftET[IO]
        payload <- payloadBytes.decodeUtf8.asError.eLiftET[IO]
      yield
        payload == "FAIL"
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "CriticalHeader" should "succeed with bad crit" in {
    List(
      "eyJhbGciOiJub25lIiwKICJjcml0Ijoic2hvdWxkbm90d29yayIKfQ.RkFJTA.",
      "eyJhbGciOiJub25lIiwKICJjcml0Ijp0cnVlCn0.bWVo.")
      .traverse { cs =>
        for
          jws <- JsonWebSignature.parse(cs).asError.eLiftET[IO]
          _ <- EitherT(jws.verify[IO]().map(_.swap.asError))
        yield
          true
      }
      .map(_.forall(identity))
      .value
      .asserting(value => assert(value.getOrElse(false)))
  }

  "CriticalHeader" should "succeed with bad crit" in {
    val payload = "This family is in a rut. We gotta shake things up. We're driving to Walley World."
    val run =
      for
        payloadBytes <- toBytes(payload)
          .eLiftET[IO]
        privateKey <- EitherT(`P-256`.ecParameterSpec.privateKey[IO](d256).asError)
        jws <- EitherT(JsonWebSignature.signBytes[IO](JoseHeader(Some(ES256), critical = Some(List("nope"))), payloadBytes,
          Some(privateKey)))
        jwsCompactSerialization <- jws.compact.eLiftET[IO]
        jws <- JsonWebSignature.parse(jwsCompactSerialization).asError.eLiftET[IO]
        publicKey <- EitherT(`P-256`.ecParameterSpec.publicKey[IO](x256, y256).asError)
        _ <- EitherT(jws.verify[IO](Some(publicKey)).map(_.swap.asError))
        _ <- EitherT(jws.check[IO](Some(publicKey), List("nope")))
        payloadBytes <- jws.decodePayload.eLiftET[IO]
        parsedPayload <- payloadBytes.decodeUtf8.asError.eLiftET[IO]
      yield
        parsedPayload == payload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

end CriticalHeaderFlatSpec
