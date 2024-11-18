package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.ecc.{`P-256`, `P-521`}
import com.peknight.jose.jwa.encryption.A128KW
import com.peknight.jose.jwa.signature.RS256
import com.peknight.jose.jwk.JsonWebKey.{EllipticCurveJsonWebKey, OctetSequenceJsonWebKey, RSAJsonWebKey}
import com.peknight.jose.jwk.PublicKeyUseType.{Encryption, Signature}
import com.peknight.security.cipher.RSA
import com.peknight.security.syntax.ecParameterSpec.publicKey
import com.peknight.validation.std.either.typed
import io.circe.syntax.*
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
        jwkSet.asJson.deepDropNullValues.noSpaces.contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx")
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
        jwkSet.asJson.deepDropNullValues.noSpaces.contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx")
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
        jwk1 <- typed[OctetSequenceJsonWebKey](jwk1).eLiftET[IO]
        key1 <- jwk1.toKey.eLiftET[IO]
        jwk2 <- jwkSet.keys.find(_.keyID.contains(KeyId("HMAC key used in JWS A.1 example"))).toRight(OptionEmpty)
          .eLiftET[IO]
        jwk2 <- typed[OctetSequenceJsonWebKey](jwk2).eLiftET[IO]
        key2 <- jwk2.toKey.eLiftET[IO]
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
        json = jwkSet.asJson.deepDropNullValues.noSpaces
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
    List(`P-256`.ecParameterSpec.publicKey[IO](x256, y256), `P-521`.ecParameterSpec.publicKey[IO](x521, y521))
      .map { io =>
        for
          publicKey <- EitherT(io.asError)
          kid = "kkiidd"
          keyID = KeyId(kid)
          webKey <- JsonWebKey.fromEllipticCurveKey(publicKey, keyID = Some(keyID), publicKeyUse = Some(Encryption))
            .eLiftET[IO]
          jwkSet = JsonWebKeySet(webKey)
          json = jwkSet.asJson.deepDropNullValues.noSpaces
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
end JsonWebKeySetFlatSpec
