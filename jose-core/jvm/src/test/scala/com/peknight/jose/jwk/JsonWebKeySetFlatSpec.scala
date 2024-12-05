package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.ecc.{`P-256`, `P-521`}
import com.peknight.jose.jwa.encryption.A128KW
import com.peknight.jose.jwa.signature.RS256
import com.peknight.jose.jwk.JsonWebKey.{EllipticCurveJsonWebKey, OctetSequenceJsonWebKey, RSAJsonWebKey}
import com.peknight.jose.jwk.PublicKeyUseType.{Encryption, Signature}
import com.peknight.jose.jwx.encodeToJson
import com.peknight.security.cipher.{AES, RSA}
import com.peknight.validation.std.either.typed
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import java.security.spec.ECPoint

class JsonWebKeySetFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKeySet" should "succeed with one bad apple" in {
    // one of the 4 jwks is missing a required parameter
    // rather than rejecting the whole thing, we want to just ignore the problematic key
    val json =
      s"""
         |{
         |  "keys": [
         |    {
         |      "kty": "EC",
         |      "kid": "96",
         |      "x": "bfOKLR8w_vD7ce9o_hmxfqTcNo9joJIALo4xC_-Qhzg",
         |      "y": "y2jXZtCaeoLGQIiJx5-kHLT3SlP7nzQbnP8SLUl1vg4",
         |      "crv": "P-256"
         |    },
         |    {
         |      "kty": "EC",
         |      "kid": "a9",
         |      "x": "msdBj_jUyuw_qCkNXTGjGpibVc_FE5FaexmE_qTWKmY",
         |      "y": "lDHAX8xJ17zRDtPcPzQmFurVtOJllmOK2jPwCGZ57TQ",
         |      "crv": "P-256"
         |    },
         |    {
         |      "kty": "EC",
         |      "kid": "this one shouldn't work 'cause there's no y",
         |      "x": "msdBj_jUyuw_qCkNXTGjGpibVc_FE5FaexmE_qTWKmY",
         |      "crv": "P-256"
         |    },
         |    {
         |      "kty": "EC",
         |      "kid": "2d",
         |      "x": "l3V6TH8tuS0vWSpZ9KcUW4oDuBzOTN0v2C_dsqkrHKw",
         |      "y": "Yhg6pR__nALI6sp68NcQM6FlPaod83xUXgHKGOCJHJ4",
         |      "crv": "P-256"
         |    }
         |  ]
         |}
      """.stripMargin
    IO.unit.asserting(_ => assert(decode[Id, JsonWebKeySet](json).map(_.keys.size == 3).getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with one unknown key type" in {
    // one of them is an unknown kty
    val json =
      """
         |{
         |  "keys": [
         |    {
         |      "kty": "EC",
         |      "kid": "96",
         |      "x": "bfOKLR8w_vD7ce9o_hmxfqTcNo9joJIALo4xC_-Qhzg",
         |      "y": "y2jXZtCaeoLGQIiJx5-kHLT3SlP7nzQbnP8SLUl1vg4",
         |      "crv": "P-256"
         |    },
         |    {
         |      "kty": "EC",
         |      "kid": "a9",
         |      "x": "msdBj_jUyuw_qCkNXTGjGpibVc_FE5FaexmE_qTWKmY",
         |      "y": "lDHAX8xJ17zRDtPcPzQmFurVtOJllmOK2jPwCGZ57TQ",
         |      "crv": "P-256"
         |    },
         |    {
         |      "kty": "UNKNOWN",
         |      "crv": "whatever",
         |      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
         |    },
         |    {
         |      "kty": "EC",
         |      "kid": "2d",
         |      "x": "l3V6TH8tuS0vWSpZ9KcUW4oDuBzOTN0v2C_dsqkrHKw",
         |      "y": "Yhg6pR__nALI6sp68NcQM6FlPaod83xUXgHKGOCJHJ4",
         |      "crv": "P-256"
         |    }
         |  ]
         |}
      """.stripMargin
    IO.unit.asserting(_ => assert(decode[Id, JsonWebKeySet](json).map(_.keys.length == 3).getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with parse example public keys" in {
    // from https://tools.ietf.org/html/draft-ietf-jose-json-web-key Appendix A.1
    val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
      "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0" +
      "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC" +
      "ur-kEgU8awapJzKnqDKgw"
    val jwkJson =
      s"""
         |{
         |  "keys":
         |    [
         |      {
         |        "kty":"EC",
         |        "crv":"P-256",
         |        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         |        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         |        "use":"enc",
         |        "kid":"1"
         |      },
         |      {
         |        "kty":"RSA",
         |        "n": "$n",
         |        "e":"AQAB",
         |        "alg":"RS256",
         |        "kid":"2011-04-29"
         |      }
         |    ]
         |}
      """.stripMargin
    IO.unit.asserting(_ => assert(decode[Id, JsonWebKeySet](jwkJson).map { jwkSet =>
      val flag1 =
        jwkSet.keys match
          case (first: EllipticCurveJsonWebKey) :: (second: RSAJsonWebKey) :: Nil => true
          case _ => false
      val flag2 =
        jwkSet.keys.find(_.keyID.contains(KeyId("1")))
          .collect {
            case jwk: EllipticCurveJsonWebKey => jwk
          }
          .exists(jwk => jwk.publicKeyUse.contains(PublicKeyUseType.Encryption) && jwk.eccPrivateKey.isEmpty)
      val flag3 =
        jwkSet.keys.find(_.keyID.contains(KeyId("2011-04-29")))
          .collect {
            case jwk: RSAJsonWebKey => jwk
          }
          .exists(jwk => jwk.privateExponent.isEmpty && jwk.algorithm.contains(RS256))
      val flag4 = !jwkSet.keys.exists(_.keyID.contains(KeyId("nope")))
      val flag5 =
        encodeToJson(jwkSet).contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx")
      flag1 && flag2 && flag3 && flag4 && flag5
    }.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with parse example private keys" in {
    // from https://tools.ietf.org/html/draft-ietf-jose-json-web-key Appendix A.2
    val jwkJson = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4" +
      "\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE" +
      "\",\"use\":\"enc\",\"kid\":\"1\"},{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhW" +
      "x4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h" +
      "4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQF" +
      "h6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_" +
      "gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp" +
      "3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPL" +
      "u4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfc" +
      "KoAC8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtj" +
      "jMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLz" +
      "gItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezs" +
      "Z-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimY" +
      "wxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8Ye" +
      "iKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3n" +
      "G8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\"qi\":\"GyM_p6JrXySiz1t" +
      "oFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55X" +
      "LSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}]}"
    IO.unit.asserting(_ => assert(decode[Id, JsonWebKeySet](jwkJson).map { jwkSet =>
      val flag1 =
        jwkSet.keys match
          case (first: EllipticCurveJsonWebKey) :: (second: RSAJsonWebKey) :: Nil => true
          case _ => false
      val flag2 =
        jwkSet.keys.find(_.keyID.contains(KeyId("1")))
          .collect {
            case jwk: EllipticCurveJsonWebKey => jwk
          }
          .exists(jwk => jwk.publicKeyUse.contains(PublicKeyUseType.Encryption) && jwk.eccPrivateKey.isDefined)
      val flag3 =
        jwkSet.keys.find(_.keyID.contains(KeyId("2011-04-29")))
          .collect {
            case jwk: RSAJsonWebKey => jwk
          }
          .exists(jwk => jwk.privateExponent.isDefined && jwk.algorithm.contains(RS256))
      val flag4 = !jwkSet.keys.exists(_.keyID.contains(KeyId("nope")))
      val flag5 =
        encodeToJson(jwkSet).contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx")
      flag1 && flag2 && flag3 && flag4 && flag5
    }.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with parse example symmetric keys" in {
    // from https://tools.ietf.org/html/draft-ietf-jose-json-web-key Appendix A.3
    val jwkJson =
      """
        |{
        |  "keys":
        |    [
        |      {
        |        "kty":"oct",
        |        "alg":"A128KW",
        |        "k":"GawgguFyGrWKav7AX4VKUg"
        |      },
        |      {
        |        "kty":"oct",
        |        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        |        "kid":"HMAC key used in JWS A.1 example"
        |      }
        |    ]
        |}
      """.stripMargin
    val run =
      for
        jwkSet <- decode[Id, JsonWebKeySet](jwkJson).eLiftET[IO]
        jwk1 <- jwkSet.keys.find(_.algorithm.contains(A128KW)).toRight(OptionEmpty).eLiftET[IO]
        key1 <- EitherT(jwk1.toKey[IO]())
        jwk2 <- jwkSet.keys.find(_.keyID.contains(KeyId("HMAC key used in JWS A.1 example"))).toRight(OptionEmpty)
          .eLiftET[IO]
        key2 <- EitherT(jwk2.toKey[IO]())
      yield
        val flag1 =
          jwkSet.keys match
            case (first: OctetSequenceJsonWebKey) :: (second: OctetSequenceJsonWebKey) :: Nil => true
            case _ => false
        flag1 && key1.getEncoded.length == 16 && key2.getEncoded.length == 64
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with from rsa public key and back" in {
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        kid = "my-key-id"
        keyID = KeyId(kid)
        webKey = JsonWebKey.fromRSAKey(publicKey, keyID = Some(keyID), publicKeyUse = Some(Signature))
        jwkSet = JsonWebKeySet(webKey)
        json = encodeToJson(jwkSet)
        parsedJwkSet <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        jwk <- parsedJwkSet.keys.find(_.keyID.contains(keyID)).toRight(OptionEmpty).eLiftET[IO]
        jwk <- typed[RSAJsonWebKey](jwk).eLiftET[IO]
        key <- EitherT(jwk.toPublicKey[IO]())
        key <- typed[RSAPublicKey](key).eLiftET
      yield
        json.contains(Signature.entryName) && json.contains(kid) && parsedJwkSet.keys.length == 1 &&
          jwk.keyType == KeyType.RSA && jwk.keyID.contains(keyID) && jwk.publicKeyUse.contains(Signature) &&
          publicKey.getModulus == key.getModulus && publicKey.getPublicExponent == key.getPublicExponent
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with from ec public key and back" in {
    List(`P-256`.publicKey[IO](x256, y256), `P-521`.publicKey[IO](x521, y521))
      .map { io =>
        for
          publicKey <- EitherT(io.asError)
          kid = "kkiidd"
          keyID = KeyId(kid)
          webKey <- JsonWebKey.fromEllipticCurveKey(publicKey, keyID = Some(keyID), publicKeyUse = Some(Encryption))
            .eLiftET[IO]
          jwkSet = JsonWebKeySet(webKey)
          json = encodeToJson(jwkSet)
          parsedJwkSet <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
          jwk <- parsedJwkSet.keys.find(_.keyID.contains(keyID)).toRight(OptionEmpty).eLiftET[IO]
          ecJsonWebKey <- typed[EllipticCurveJsonWebKey](jwk).eLiftET
          parsedPublicKey <- EitherT(ecJsonWebKey.toPublicKey[IO]())
          parsedPublicKey <- typed[ECPublicKey](parsedPublicKey).eLiftET[IO]
        yield
          given CanEqual[java.security.spec.EllipticCurve, java.security.spec.EllipticCurve] = CanEqual.derived
          given CanEqual[ECPoint, ECPoint] = CanEqual.derived
          json.contains(Encryption.entryName) && json.contains(kid) && parsedJwkSet.keys.length == 1 &&
            jwk.keyType == KeyType.EllipticCurve && jwk.keyID.contains(keyID) &&
            jwk.publicKeyUse.contains(Encryption) && publicKey.getW.getAffineX == parsedPublicKey.getW.getAffineX &&
            publicKey.getW.getAffineY == parsedPublicKey.getW.getAffineY &&
            publicKey.getParams.getCofactor == parsedPublicKey.getParams.getCofactor &&
            publicKey.getParams.getCurve == parsedPublicKey.getParams.getCurve &&
            publicKey.getParams.getGenerator == parsedPublicKey.getParams.getGenerator &&
            publicKey.getParams.getOrder == parsedPublicKey.getParams.getOrder
      }
      .sequence
      .map(_.forall(identity))
      .value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with oct and default to json" in {
    val run =
      for
        key1 <- EitherT(AES.keySizeGenerateKey[IO](128).asError)
        key2 <- EitherT(AES.keySizeGenerateKey[IO](128).asError)
        jwk1 <- JsonWebKey.fromKey(key1).eLiftET[IO]
        jwk2 <- JsonWebKey.fromKey(key2).eLiftET[IO]
        jwks = JsonWebKeySet(jwk1, jwk2)
        json = encodeToJson(jwks)
        newJwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
      yield
        json.contains("\"k\"") && jwks.keys.length == newJwks.keys.length
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with oct keys length" in {
    val run =
      for
        jwk1 <- decode[Id, OctetSequenceJsonWebKey]("""{"kty":"oct","k":"bbj4v-CvqwOm1q3WkVJEpw"}""").eLiftET[IO]
        jwk2 <- decode[Id, OctetSequenceJsonWebKey]("""{"kty":"oct","k":"h008v_ab_Z-N7q13D-JabC"}""").eLiftET[IO]
        jwk3 <- decode[Id, OctetSequenceJsonWebKey]("""{"kty":"oct","k":"-_-8888888888888888-_-"}""").eLiftET[IO]
        jwk4 <- decode[Id, OctetSequenceJsonWebKey]("""{"kty":"oct","k":"__--_12_--33--_21_--__"}""").eLiftET[IO]
        jwks = JsonWebKeySet(jwk1, jwk2, jwk3, jwk4)
      yield
        jwks.keys.length == 4
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with parse set containing invalid" in {
    val json =
      """
        |{
        |    "keys": [
        |        {
        |            "kty": "EC",
        |            "crv": "NOPERS",
        |            "kid": "iRTU",
        |            "x": "tcjSy7nIVZ2DVz-RKjqHIJqr5WDqZLS6fq4rEN6pfGY",
        |            "y": "2oqx5jvggJKy-LXFjpDOpL0g_SbiLylu_8xx-dBMQeQ"
        |        },
        |        {
        |            "kty": "EC",
        |            "x": "riwTtQeRjmlDsR4PUQELhejpPkZkQstb0_Lf08qeBzM",
        |            "y": "izN8y6z-8j8bB_Lj10gX9mnaE_E0ZK5fl0hJVyLWMKA",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": false,
        |            "x": "GS2tEeCRf0CFHzI_y68XiLzqa9-RpG4Xn-dq2lPtShY",
        |            "y": "Rq6ybA7IbjhDTfvP2GSzxEql8II7RvRPb3mJ6tzZUgI",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": "EC",
        |            "x": "IiIIM4W-HDen_11XiGlFXh1kOxKcX1YB5gqMrCM-hMM",
        |            "y": "57-3xqdddSBBarwwXcWu4hIG4dAlIiEYdy4aaFGb57s",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": "EC",
        |            "x": [
        |                "IiIIM4W-HDen_11XiGlFXh1kOxKcX1YB5gqMrCM-hMM",
        |                "huh"
        |            ],
        |            "y": "57-3xqdddSBBarwwXcWu4hIG4dAlIiEYdy4aaFGb57s",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": "EC",
        |            "x": "rO8MozDmEAVZ0B5zQUDD8PGosFlwmoMmi7I-1rspWz4",
        |            "y": "I6ku1iUzFJgTnjNzjAC1sSGkYfiDqs-eEReFMLI-6n8",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": 1,
        |            "x": "IiIIM4W-HDen_11XiGlFXh1kOxKcX1YB5gqMrCM-hMM",
        |            "y": "57-3xqdddSBBarwwXcWu4hIG4dAlIiEYdy4aaFGb57s",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": 885584955514411149933357445595595145885566661,
        |            "x": "IiIIM4W-HDen_11XiGlFXh1kOxKcX1YB5gqMrCM-hMM",
        |            "y": "57-3xqdddSBBarwwXcWu4hIG4dAlIiEYdy4aaFGb57s",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": {
        |                "EC": "EC"
        |            },
        |            "x": "riwTtQeRjmlDsR4PUQELhejpPkZkQstb0_Lf08qeBzM",
        |            "y": "izN8y6z-8j8bB_Lj10gX9mnaE_E0ZK5fl0hJVyLWMKA",
        |            "crv": "P-256"
        |        },
        |        {
        |            "kty": null,
        |            "x": "riwTtQeRjmlDsR4PUQELhejpPkZkQstb0_Lf08qeBzM",
        |            "y": "izN8y6z-8j8bB_Lj10gX9mnaE_E0ZK5fl0hJVyLWMKA",
        |            "crv": "P-256"
        |        }
        |    ]
        |}
      """.stripMargin
    IO.unit.asserting(_ => assert(decode[Id, JsonWebKeySet](json).map(_.keys.length == 3).getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with okps ok" in {
    val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
      "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0" +
      "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC" +
      "ur-kEgU8awapJzKnqDKgw"
    val json =
      s"""
        |{
        |  "keys":
        |    [
        |      {
        |        "kty":"EC",
        |        "crv":"P-256",
        |        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        |        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        |        "use":"enc",
        |        "kid":"1"
        |      },
        |      {
        |        "kty":"OKP",
        |        "crv":"Ed448",
        |        "x":"LzuoHViWG285WNae4BAFKg44npQyMRqcON7_nt9J0fJBy2zqimJTTSi0SmHqfu0GwUIXIMg7vl2A"
        |      },
        |      {
        |        "kty":"OKP",
        |        "crv":"Ed25519",
        |        "x":"5gsMTcjHtfvEXwZuvmkEgvldWK1NHXjg6qOzC1NzsnI"
        |      },
        |      {
        |        "kty":"OKP",
        |        "crv":"X448",
        |        "x":"ujkHCs4gobVjp7P_CfTzydh9ue3jrSh8TaIh_uNsr4kXWRGibT7OBaYxudHn5dVMfQEEPD0RwacA"
        |      },
        |      {
        |        "kty":"OKP",
        |        "crv":"X25519",
        |        "x":"XQGokbde5czDzRvEDPFSv3jYglZN1R9upLJCfFO_-lA"
        |      },
        |      {
        |        "kty":"RSA",
        |        "n": "$n",
        |        "e":"AQAB",
        |        "alg":"RS256",
        |        "kid":"2011-04-29"
        |      }
        |    ]
        |}
      """.stripMargin
    IO.unit.asserting(_ => assert(
      decode[Id, JsonWebKeySet](json)
        .map(_.keys.length)
        .map(length => 2 <= length && length <= 6)
        .getOrElse(false)
    ))
  }

  /*
   * 2 tests to look at http://www.ietf.org/mail-archive/web/jose/current/msg04297.html
   * and see/ensure that we can consume JWK input that's not strictly conforming while also
   * producing conforming output
   */

  "JsonWebKeySet" should "succeed with salesforce" in {
    // ~8am Aug 26, '14 from https://login.salesforce.com/id/keys
    val jwks = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AMCELStParLtaggkLtZh4enfxMsjpW6jAlfFjGnDsoWZ4NbG2hSWPtDyB-OisNbo" +
      "Y2x4PeP69lBC2Hd9LxfMcFYhoQpqT7khoZMTaE-QjKCT0uiVvswaUe7Lh6gVJ2hnWehtrmGQ6cFmLP-EiQ7ls8VQa0KiDP2VYFKrrZ4kD5ozA" +
      "F-TKs5wU5xt85u9vAZjc0u09oLc8bN4wIA7EgLtysadw-jQxhEYWgCfIzoMB75kCucRYvQHcO7L9pwh_sDPguXyyWJqRjkq0z9Ryzpavvk0Tg" +
      "L1i_YHDRHquGq68iGLsebMoOuqx0_FNlIW9T3V7e0XkGPMAZz9gQR9UB-68zme1G6hS20FELGRQFTHH5u4CTfCVi5XEiWXQts2mNMCOavD1jf" +
      "jfxoACuuBSmUO6QdG0UOQEMfg91OLGBOBHIEr1fH1vOj2hdVV2hzBXKJuPIGdRsxP1dubj2_tMrntHL_ZXo6yCg70YieVIslD6Ya6OAMNmXA4" +
      "v_K_K6n4JVoXJweGxkq4uJBAW_yHcL6isEQqsZTXUZ1NaKEHlAWlUcHW6Y9t2darWIweeVn9ijgiensDMnXauGxABuiiKj5rLE-_3sb8oFMrl" +
      "uqoZwlfoE2RMBSNAOnY7BzOYrX5MzWOOwXrgLRl47mkZ1WCBL0650o9y8e2H7wiIhqhaxust9QJ\",\"e\":\"AQAB\",\"alg\":\"RS256" +
      "\",\"use\":\"sig\",\"kid\":\"188\"},{\"kty\":\"RSA\",\"n\":\"AKPBc9I142dEc-Srdk5sz9MVaJH_kOAM_jEIOYuTAsTTU0Im" +
      "ae1ZMAGXjNJifpig2wsz5vcLON7_HMXoiJFWUKqwKHJ52_dDAwp1Pu6A-zLzlOEm5obi81QslWTyAUauc9DoI3MC3g-LazqKIJCzrtJMrssza" +
      "BZK-9dpvxmdcYnPl9DJRSqt_tnCOFNpxLrofl3Mu21KgsdM0yRTzjioIRmBGWem4mdOFQvhEXFunAtfaRFpurwqmSRLCjwn2s1QKBymQLpDXd" +
      "Fyz0Hf1usQGhp6fHu2ubRR5-nVOopISPeGYnlaeliLVrEEw8CR_g-21aVURvpVi--JYHLkHRQLZXZv_5Oxb5U13aoi63dK2Lg50xYsFErFF1g" +
      "SW5hlbBDspWVT0AC_iuxu6dwUWOF9urzoH5bncAjo-y-1hW3dCF84k5u-MXtimRirBaaAoySNM_w-TnuW6H7MK9Qnmn4Zfe7LhuzqCJ6G7e0A" +
      "EJ5y3AVc1D8_035Tlw3OVInj6bQNG8XXfDFRDYg20xhjc-gws3y_fOkH3CSzwfGmWt5RTdJFjwZDnJWWoC-FqciJZQenrr2doX6bfCGNv25lD" +
      "dOpbqOjexctIUkhTFr382g_PxX93M29Sr_m9MSOlIJOHeu0TTUm03ETNjLr8fnSYDsl6q3P4RPejjqnDI6xmSaF5wgD\",\"e\":\"AQAB\"," +
      "\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"190\"},{\"kty\":\"RSA\",\"n\":\"AJznEDrx1fK3PoXHz_0ZsTBo8lZa7ki3h" +
      "V06I2HG4sWgB9-rHFHo42sLN9aK1I5mKgeYrBPZ7XbC-A57HT_zAydprWA9hSIfLQZCY4F4rY3XA3Ja8BCwMfOOsASJUhEvMEenM6XSWX0sIS" +
      "__dhBqQx-s-5ShApaoQ5W7WfshShY_QUEcGhF1le7rqtt4MVzqshDdFl5d2ST4LKHQp5V0Z_cv6-QjVfVeML81xpSYU9zb_zf2eVzWSI2Zx3Q" +
      "rhP4rU-GtcRDRBHbOyY4OZkU5VRc2L-YkLQaO43WOaIDE4Cj5kYeoWLqi3pItwDgFH39QBmjfU2R-tFMcE8NN_g0CS-Qtkrgv7zOSiFsWcUJ4" +
      "rm33oFAgV6SUgCWy7fM0hc7U3Ky0uPsIFB6NQPEwzWjtvPyrAVE1rK4njq9zXwp-GzzW-7fBvdFOtJVtBiIRHWt3zWJ1dFlqWVTtYwkTcvyWF" +
      "LNxAqNBNWUCWQ-9g5ulI4rh-3kd2YDSkfbZSzXcmUqWVGTxKy61yfdHeV25iWL0V_a_d8-hkKjr-RUMtSYWrcHn8YSncoZAxB7KhCztFw6pw5" +
      "5oMZBBFPpR2ElRs_og5VGTlGE0wrcbDw5gSFzjLsKdFMnSaYTt-qkUGg8hIxzbGCi4-Slb4wx0vBsNRYWxb7KFKwR63uIS2PT2uZnmrVf5\"," +
      "\"e\":\"AQAB\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"192\"}]}"
    val run =
      for
        jsonWebKeySet <- decode[Id, JsonWebKeySet](jwks).eLiftET[IO]
        jwk188 <- jsonWebKeySet.keys
          .find(jwk => jwk.keyID.contains(KeyId("188")) && jwk.publicKeyUse.contains(Signature))
          .toRight(OptionEmpty)
          .eLiftET[IO]
        jwk188 <- typed[RSAJsonWebKey](jwk188).eLiftET[IO]
        publicKey <- EitherT(jwk188.toPublicKey[IO]())
        jwk188 <- JsonWebKey.fromKey(publicKey).eLiftET[IO]
        jwk188 <- typed[RSAJsonWebKey](jwk188).eLiftET[IO]
        modulus188 <- jwk188.modulus.decode[Id].eLiftET[IO]
      yield
        jsonWebKeySet.keys.length == 3 && modulus188.headOption.exists(_ != 0)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySet" should "succeed with google" in {
    // ~8am Aug 26, '14 from https://www.googleapis.com/oauth2/v2/certs
    // Fu*k google.
    val n1 = "vl9eiLnGMX7r0f7i7sSqCN5zpISYRtqrZA8JfcVSq3FrqZFoUNcMCDbSaWGzWWCTkvN3jQEkgYpCpwRAOMYM08IXm46UwxMWlcb8c4" +
      "7LGbdFWzyf3t_3FcqASMp6BuEnCCciifAcDeiqG4JYmkux-KUSWYjXGFOxgjL0xZ4M3O8="
    val n2 = "x_s89G0aZsHdL81sgDN8-zPi9oq-5rlP5j850QllJUMD4PBEEo9KnfoKC9WaSJ2_oOI3W8KOLk4i993J4IGzJFlrNKt2xNSL60iQ9n" +
      "DwGMhIXnieGyXosKRXhepaySCBQysuW8OiVlDVEoFS2VHvC_6bt5QZaitl7AYZxPoPujk="
    val jwks =
      s"""
         |{
         |  "keys": [
         |    {
         |      "kty": "RSA",
         |      "alg": "RS256",
         |      "use": "sig",
         |      "kid": "ce808d4fb2eabff22a608e0c7a14300cc04f2606",
         |      "n": "$n1",
         |      "e": "AQAB"
         |    },
         |    {
         |      "kty": "RSA",
         |      "alg": "RS256",
         |      "use": "sig",
         |      "kid": "ce3dde4df07fe0794fcff86642b4b11f8026f43f",
         |      "n": "$n2",
         |      "e": "AQAB"
         |    }
         |  ]
         |}
      """.stripMargin
    val run =
      for
        jsonWebKeySet <- decode[Id, JsonWebKeySet](jwks)
        json = encodeToJson(jsonWebKeySet)
      yield
        jsonWebKeySet.keys.length == 2 && !json.contains("=")
    IO.unit.asserting(_ => assert(run.getOrElse(false)))
  }
end JsonWebKeySetFlatSpec
