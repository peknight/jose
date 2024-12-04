package com.peknight.jose.jwa.signature

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jws.JsonWebSignatureTestOps.testBasicRoundTrip
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.signature.{Ed25519, Ed448}
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
        jkt <- EitherT(jwk.calculateBase64UrlEncodedThumbprint[IO]())
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        jwsSigner <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(EdDSA)), expectedPayload, Some(privateKey)))
        jws <- jwsSigner.compact.eLiftET[IO]
        jwkPubOnly <- decode[Id, AsymmetricJsonWebKey](jwkJsonPubOnly).eLiftET[IO]
        jktPublicOnly <- EitherT(jwkPubOnly.calculateBase64UrlEncodedThumbprint[IO]())
        publicKey <- EitherT(jwkPubOnly.toPublicKey[IO]())
        jwsVerifier <- JsonWebSignature.parse(expectedJws).eLiftET[IO]
        _ <- EitherT(jwsVerifier.check[IO](Some(publicKey)))
        payload <- jwsVerifier.decodePayloadString().eLiftET[IO]
        alteredJwsVerifier <- JsonWebSignature.parse(alteredJws).eLiftET[IO]
        _ <- EitherT(alteredJwsVerifier.check[IO](Some(publicKey)).map(_.swap.asError))
      yield
        jkt.value == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" && jws == expectedJws &&
          jktPublicOnly.value == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" && payload == expectedPayload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "EdDSA" should "succeed with verify produced else where" in {
    val jwkJson1 = """{"kty":"OKP","crv":"Ed25519","x":"sipir4_DXRPiq3vgQPbX5EIZjhdxFVO0bwcVnIFZxQA"}"""
    val jwkJson2 = "{\"kty\":\"OKP\",\"d\":\"-g8nVY3FlaY9SNE1c5Edn6kQXXQN13SVLCmdlKYgqYM\",\"crv\":\"Ed25519\",\"x" +
      "\":\"sipir4_DXRPiq3vgQPbX5EIZjhdxFVO0bwcVnIFZxQA\"}"
    val jws = "eyJhbGciOiJFZERTQSJ9.bWVo.BieQMHmbP-qyMnrbUV_mySYcoDqaxTrQGkGOZ5KGcAZ_8uwwSlds62O8yeHvp5sc4FnEas8XbJi" +
      "lf3-FQbQrAQ"
    val run =
      for
        jwk1 <- decode[Id, AsymmetricJsonWebKey](jwkJson1).eLiftET[IO]
        publicKey <- EitherT(jwk1.toPublicKey[IO]())
        jwsObject1 <- JsonWebSignature.parse(jws).eLiftET[IO]
        _ <- EitherT(jwsObject1.check[IO](Some(publicKey)))
        payload <- jwsObject1.decodePayloadString().eLiftET[IO]
        jwk2 <- decode[Id, AsymmetricJsonWebKey](jwkJson2).eLiftET[IO]
        privateKey <- EitherT(jwk2.toPrivateKey[IO]())
        jwsObject2 <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(EdDSA)), "meh", Some(privateKey)))
        compact <- jwsObject2.compact.eLiftET[IO]
      yield
        payload == "meh" && compact == jws
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "EdDSA" should "succeed with Ed25519 round trip gen keys" in {
    val run =
      for
        keyPair1 <- EitherT(Ed25519.generateKeyPair[IO]().asError)
        keyPair2 <- EitherT(Ed25519.generateKeyPair[IO]().asError)
        _ <- testBasicRoundTrip("Little Ed", EdDSA, keyPair1.getPrivate, keyPair1.getPublic, keyPair2.getPrivate,
          keyPair2.getPublic)
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "EdDSA" should "succeed with Ed448 round trip gen keys" in {
    val run =
      for
        keyPair1 <- EitherT(Ed448.generateKeyPair[IO]().asError)
        keyPair2 <- EitherT(Ed448.generateKeyPair[IO]().asError)
        _ <- testBasicRoundTrip("Big Ed", EdDSA, keyPair1.getPrivate, keyPair1.getPublic, keyPair2.getPrivate,
          keyPair2.getPublic)
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "EdDSA" should "succeed with Ed mixed round trip gen keys" in {
    val run =
      for
        keyPair1 <- EitherT(Ed25519.generateKeyPair[IO]().asError)
        keyPair2 <- EitherT(Ed448.generateKeyPair[IO]().asError)
        _ <- testBasicRoundTrip("Cousin Eddie", EdDSA, keyPair1.getPrivate, keyPair1.getPublic, keyPair2.getPrivate,
          keyPair2.getPublic)
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }
end EdDSAFlatSpec
