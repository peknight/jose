package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.ecc.`P-256`
import com.peknight.jose.jwk.JsonWebKey.*
import com.peknight.jose.jwk.KeyOperationType.*
import com.peknight.jose.jwx.encodeToJson
import com.peknight.security.cipher.RSA
import com.peknight.validation.std.either.typed
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.interfaces.*

class JsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private def isRSA(jwk: JsonWebKey): EitherT[IO, Error, Unit] =
    for
      jwk <- typed[RSAJsonWebKey](jwk).eLiftET[IO]
      publicKey <- EitherT(jwk.toPublicKey[IO]())
      publicKey <- typed[RSAPublicKey](publicKey).eLiftET[IO]
    yield
      ()

  private def isEllipticCurve(jwk: JsonWebKey): EitherT[IO, Error, Unit] =
    for
      jwk <- typed[EllipticCurveJsonWebKey](jwk).eLiftET[IO]
      publicKey <- EitherT(jwk.toPublicKey[IO]())
      publicKey <- typed[ECPublicKey](publicKey).eLiftET[IO]
    yield
      ()

  "JsonWebKey" should "succeed with factory with X octet key pair json web key" in {
    val jwkJson = "{\"kty\":\"OKP\",\"d\":\"T4gjxXciGdlPcWC1Pgba0cptraIx8ZjORUyR-ttweZQ\",\"crv\":\"X25519\",\"x\":" +
      "\"qPRE1ElE6NArtJ0rhMkjaR8_PJZLf6v6Zk_4Vo72jho\"}"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        jwk <- typed[OctetKeyPairJsonWebKey](jwk).eLiftET[IO]
        publicKey <- EitherT(jwk.toPublicKey[IO]())
        publicKey <- typed[XECPublicKey](publicKey).eLiftET[IO]
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        privateKey <- typed[XECPrivateKey](privateKey).eLiftET[IO]
      yield
        jwk.keyType == KeyType.OctetKeyPair
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "succeed with factory with Ed octet key pair json web key" in {
    val jwkJson = "{\"kty\":\"OKP\",\"d\":\"Y6KQHffZKlIXW1JdVvEBJCliWtuYk3pYQJoeSvfJEAw\",\"crv\":\"Ed25519\",\"x\":" +
      "\"Jp1b9nhTp_Z2YmHC22k5oy32dIIWYOhiaD8PJQFcxgU\"}"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        jwk <- typed[OctetKeyPairJsonWebKey](jwk).eLiftET[IO]
        publicKey <- EitherT(jwk.toPublicKey[IO]())
        publicKey <- typed[EdECPublicKey](publicKey).eLiftET[IO]
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        privateKey <- typed[EdECPrivateKey](privateKey).eLiftET[IO]
      yield
        jwk.keyType == KeyType.OctetKeyPair
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "succeed with factory with RSA public key" in {
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        jwk <- JsonWebKey.fromKey(publicKey).eLiftET[IO]
        _ <- isRSA(jwk)
      yield
        jwk.keyType == KeyType.RSA
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "failed with factory with RSA private key" in {
    RSA.privateKey[IO](n, d).asserting(privateKey => assert(JsonWebKey.fromKey(privateKey).isLeft))
  }

  "JsonWebKey" should "succeed with factory with EC public key" in {
    val run =
      for
        publicKey <- EitherT(`P-256`.publicKey[IO](x256, y256).asError)
        jwk <- JsonWebKey.fromKey(publicKey).eLiftET[IO]
        _ <- isEllipticCurve(jwk)
      yield
        jwk.keyType == KeyType.EllipticCurve
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "failed with factory with EC private key" in {
    `P-256`.privateKey[IO](d256).asserting(privateKey => assert(JsonWebKey.fromKey(privateKey).isLeft))
  }

  "JsonWebKey" should "succeed with EC single jwk to and from json" in {
    val jwkJson =
      """
        |{
        |  "kty":"EC",
        |  "crv":"P-256",
        |  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        |  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        |  "use":"enc",
        |  "kid":"1"
        |}
      """.stripMargin
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        _ <- isEllipticCurve(jwk)
        jsonOut = encodeToJson(jwk)
        jwk2 <- decode[Id, JsonWebKey](jsonOut).eLiftET[IO]
        _ <- isEllipticCurve(jwk2)
      yield
        true
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "succeed with RSA single jwk to and from json" in {
    val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
      "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0" +
      "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC" +
      "ur-kEgU8awapJzKnqDKgw"
    val jwkJson =
      s"""
        |{
        |  "kty":"RSA",
        |  "n": "$n",
        |  "e":"AQAB",
        |  "alg":"RS256"
        |}
      """.stripMargin
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        _ <- isRSA(jwk)
        jsonOut = encodeToJson(jwk)
        jwk2 <- decode[Id, JsonWebKey](jsonOut).eLiftET[IO]
        _ <- isRSA(jwk2)
      yield
        true
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "succeed with key ops" in {
    val json1 = """{"kty":"oct","k":"Hdd5Uqtga_B4UilmahWJR8juxF_zw1_xaWeUGAvbg9c"}"""
    val json2 = """{"kty":"oct","key_ops":["decrypt","encrypt"],"k":"add14qyge_v4sscm2hWJR8juxF_____cpW8U3ahcp__"}"""
    val run =
      for
        jwk1 <- decode[Id, OctetSequenceJsonWebKey](json1).eLiftET[IO]
        keyOps = List(decrypt, deriveBits, deriveKey, encrypt, sign, verify, unwrapKey, wrapKey)
        json1 = encodeToJson(jwk1.copy(keyOperations = Some(keyOps)))
        parsedJwk1 <- decode[Id, OctetSequenceJsonWebKey](json1).eLiftET[IO]
        jwk2 <- decode[Id, OctetSequenceJsonWebKey](json2).eLiftET[IO]
      yield
        jwk1.keyOperations.isEmpty && json1.contains("\"key_ops\"") && parsedJwk1.keyOperations.contains(keyOps) &&
          jwk2.keyOperations.exists(keyOps => keyOps.length == 2 && keyOps.contains(encrypt) && keyOps.contains(decrypt))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "failed with handle wrong type 1" in {
    assert(decode[Id, JsonWebKey]("""{"kty":1}""").isLeft)
  }

  "JsonWebKey" should "failed with handle wrong type 2" in {
    assert(decode[Id, JsonWebKey](
      s"""
         |{
         |  "kty":"RSA",
         |  "n": 8929747471717373711113313454114,
         |  "e":"AQAB",
         |  "alg":"RS256"
         |}
      """.stripMargin
    ).isLeft)
  }

  "JsonWebKey" should "failed with handle wrong type 3" in {
    assert(decode[Id, JsonWebKey](
      s"""
         |{ "kty":"EC",
         |  "crv":"P-256",
         |  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         |  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         |  "use":true,
         |  "kid":"1"
         |}
      """.stripMargin
    ).isLeft)
  }

  "JsonWebKey" should "failed with handle wrong type 4" in {
    assert(decode[Id, JsonWebKey](
      s"""
         |{
         |  "kty":"EC",
         |  "crv":"P-256",
         |  "x":["MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"],
         |  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         |  "kid":"1s"
         |}
      """.stripMargin
    ).isLeft)
  }
end JsonWebKeyFlatSpec
