package com.peknight.jose.jwa.signature

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec

class EdDSAFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "EdDSA" should "succeed with RFC8037 appendix A1 to A5" in {
    val jwkJson = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":" +
      "\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
    val expectedPayload = "Example of Ed25519 signing"
    val expectedJws = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg" +
      "3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
    val jwkJsonPubOnly = """{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"""
    val alteredJws = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjX0JzlnLWG1PPOt7-09PGcvMg3" +
      "AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
    val run =
      for
        jwk <- decode[Id, AsymmetricJsonWebKey](jwkJson).eLiftET[IO]
        _ = println(1)
        jkt <- EitherT(jwk.calculateBase64UrlEncodedThumbprint[IO]())
        _ = println(2)
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        _ = println(3)
        jwsSigner <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(EdDSA)), expectedPayload, Some(privateKey)))
        _ = println(4)
        jws <- jwsSigner.compact.eLiftET[IO]
        _ = println(5)
        jwkPubOnly <- decode[Id, AsymmetricJsonWebKey](jwkJsonPubOnly).eLiftET[IO]
        _ = println(6)
        jktPublicOnly <- EitherT(jwkPubOnly.calculateBase64UrlEncodedThumbprint[IO]())
        _ = println(7)
        publicKey <- EitherT(jwkPubOnly.toPublicKey[IO]())
        _ = println(8)
        jwsVerifier <- JsonWebSignature.parse(expectedJws).asError.eLiftET[IO]
        _ = println(9)
        _ <- EitherT(jwsVerifier.check[IO](Some(publicKey)))
        _ = println(10)
        payload <- jwsVerifier.decodePayloadUtf8.eLiftET[IO]
        _ = println(11)
        alteredJwsVerifier <- JsonWebSignature.parse(alteredJws).asError.eLiftET[IO]
        _ = println(12)
        _ <- EitherT(alteredJwsVerifier.check[IO](Some(publicKey)).map(_.swap.asError))
        _ = println(13)
      yield
        jkt.value == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" && jws == expectedJws &&
          jktPublicOnly.value == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" && payload == expectedPayload
    run.value.asserting(value =>
      println(value)
      assert(value.getOrElse(false)))
  }


end EdDSAFlatSpec
