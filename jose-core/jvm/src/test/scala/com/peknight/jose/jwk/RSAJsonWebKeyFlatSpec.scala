package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwk.JsonWebKey.{AsymmetricJsonWebKey, RSAJsonWebKey}
import com.peknight.security.cipher.RSA
import com.peknight.validation.std.either.typed
import io.circe.syntax.*
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.interfaces.RSAPrivateCrtKey
import java.security.{PrivateKey, PublicKey}

class RSAJsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  // key from http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-13#appendix-A.3.1
  // it was shown as octets in -11 and before
  private val rsaJwkWithPrivateKey: String = "{\"kty\":\"RSA\", \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbj" +
    "i9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_" +
    "7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5Ih" +
    "lJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\", \"e\":\"AQAB\", \"d\":\"Eq5xpGn" +
    "NCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0Bk" +
    "TGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4eh" +
    "NYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopz" +
    "nQ\"}"
  "RSAJsonWebKey" should "succeed with parse example with private" in {
    val run =
      for
        jwk <- decode[Id, JsonWebKey](rsaJwkWithPrivateKey).eLiftET[IO]
        jwk <- typed[RSAJsonWebKey](jwk).eLiftET[IO]
        parsedPublicKey <- EitherT(jwk.toPublicKey[IO]())
        parsedPrivateKey <- EitherT(jwk.toPrivateKey[IO]())
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
      yield
        given CanEqual[PublicKey, PublicKey] = CanEqual.derived
        given CanEqual[PrivateKey, PrivateKey] = CanEqual.derived
        parsedPublicKey == publicKey && parsedPrivateKey == privateKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSAJsonWebKey" should "succeed with from key with private" in {
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        jwk <- JsonWebKey.fromPublicKey(publicKey).eLiftET[IO]
        jsonNoPrivateKey = jwk.asJson.deepDropNullValues.noSpaces
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        jwk <- JsonWebKey.fromPublicKey(publicKey, Some(privateKey)).eLiftET[IO]
        jsonExcludePrivateKey = jwk.excludePrivate.asJson.deepDropNullValues.noSpaces
        json = jwk.asJson.deepDropNullValues.noSpaces
      yield
        !jsonExcludePrivateKey.contains("\"d\"") && jsonNoPrivateKey == jsonExcludePrivateKey && json.contains("\"d\"")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSAJsonWebKey" should "succeed with from key with crt private and back and again" in {
    val json = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFx" +
      "uhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY" +
      "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksI" +
      "NHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5" +
      "E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_n" +
      "HNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK" +
      "66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\"p\":\"83i-7IvM" +
      "GXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyq" +
      "VWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuq" +
      "nb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9" +
      "LUnADun4vIcb6yelxk\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4" +
      "c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH" +
      "9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb" +
      "_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3" +
      "rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFY" +
      "ItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}"
    doKeyWithCrtPrivateAndBackAndAgain(json)
  }

  "RSAJsonWebKey" should "succeed with from crt and back with jws appendix A2" in {
    val json = "{\"kty\":\"RSA\",\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJr" +
      "cS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5re" +
      "xMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAc" +
      "o9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\",\"e\":\"AQAB\",\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2" +
      "JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6" +
      "f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1Zd" +
      "iYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\",\"p\":\"4BzEEOtI" +
      "pmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGB" +
      "Y5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\",\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtC" +
      "oHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypee" +
      "F6689rjcJIDEz9RWdc\",\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_" +
      "PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\",\"dq\":\"h_96-" +
      "mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-k" +
      "yNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\",\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-Dlc" +
      "xyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A560" +
      "3k2-ZQwVK0JKSHuLFkuQ3U\"}"
    doKeyWithCrtPrivateAndBackAndAgain(json)
  }

  private def doKeyWithCrtPrivateAndBackAndAgain(json: String): IO[Assertion] =
    val run =
      for
        jwk <- decode[Id, AsymmetricJsonWebKey](json).eLiftET[IO]
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        privateKey <- typed[RSAPrivateCrtKey](privateKey).eLiftET[IO]
        jsonExcludePrivate = jwk.excludePrivate.asJson.deepDropNullValues.noSpaces
        json = jwk.asJson.deepDropNullValues.noSpaces
        jwkAgain <- decode[Id, AsymmetricJsonWebKey](json).eLiftET[IO]
        privateKeyAgain <- EitherT(jwkAgain.toPrivateKey[IO]())
        privateKeyAgain <- typed[RSAPrivateCrtKey](privateKeyAgain).eLiftET[IO]
      yield
        given CanEqual[PrivateKey, PrivateKey] = CanEqual.derived
        List("d", "p", "q", "dp", "dq", "qi").map(k => s"\"$k\"")
          .forall(k => !jsonExcludePrivate.contains(k) && json.contains(k)) &&
          privateKey == privateKeyAgain
    run.value.asserting(value => assert(value.getOrElse(false)))

  "RSAJsonWebKey" should "succeed with to json with public key only jwk and include private settings" in {
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        jwk <- JsonWebKey.fromPublicKey(publicKey).eLiftET[IO]
        jsonExcludePrivate = jwk.excludePrivate.asJson.deepDropNullValues.noSpaces
        jwk <- decode[Id, AsymmetricJsonWebKey](jsonExcludePrivate).eLiftET[IO]
        json = jwk.asJson.deepDropNullValues.noSpaces
      yield
        jsonExcludePrivate == json
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end RSAJsonWebKeyFlatSpec
