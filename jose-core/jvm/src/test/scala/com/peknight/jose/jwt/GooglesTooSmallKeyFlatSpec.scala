package com.peknight.jose.jwt

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKeySet
import com.peknight.jose.jwx.JoseConfig
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class GooglesTooSmallKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  /**
   * ~ May 2015 Google's JWKS URI https://www.googleapis.com/oauth2/v3/certs for OIDC had 1024 bit RSA keys in it that
   * were being used to sign ID tokens.
   * That goes against the min of 2048 in https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.3
   * "A key of size 2048 bits or larger MUST be used with [RS256, etc]"
   *
   * These are some tests to check that we do, by default, enforce the key size (it's been that way for a long time)
   * but that there are easy workarounds possible at the JwtConsumer[Builder] layer.
   *
   * The example content was from Google May 14th '15
   *
   * A bug report was submitted to them on May 19 2-4355000007039 but we'll see if anything comes of it.
   * Exposing the setRelaxXXXKeyValidations on JwtConsumer[Builder] will probably be useful in other ways.
   *
   * On July 8, 2015 I was informed that they moved to using 2048 bit RSA keys (thanks William!) and was asked to test
   * it. The new test here checks that things work as expected.
   */
  private val idToken: String = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc2ZmQzMmFlYzdlMGY4YzE5MGRkYThiOWRkODVlN2NmNWFkMzNjNDM" +
    "ifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTE2MzA4NDA4MzE0NjYxNDc4MTMyIiwiYXpwIjoiODIyNzM3NTU1NDI5LWV" +
    "2dmtkMDBvdHFyNWdsMTEwbmZhcGlzamZvZWEzNmpmLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJqa3Rlc3QxQG1hcml0aW" +
    "1lc291cmNlLmNhIiwiYXRfaGFzaCI6Im85bUZjZUx6QV9ZMnhmNEJqVmdOQmciLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXVkIjoiODIyNzM3N" +
    "TU1NDI5LWV2dmtkMDBvdHFyNWdsMTEwbmZhcGlzamZvZWEzNmpmLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaGQiOiJtYXJpdGltZXNv" +
    "dXJjZS5jYSIsIm9wZW5pZF9pZCI6Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vYWNjb3VudHMvbzgvaWQ_aWQ9QUl0T2F3bGIxSEhFZFJJZW00d2Z" +
    "1MXFNY1BUdWZvUDZzTi11ZVVrIiwiaWF0IjoxNDMxNjEyMjM4LCJleHAiOjE0MzE2MTU4Mzh9.RRMVpR9WJrkddegS4uKNT7rTov-LvRQ9sCtGo" +
    "_SXrqkNbLZgArSJcmmHHxoQDsVWUjl2ZNG-7ZjDRuMu-POJLR4GHpwmQ8gttAEeywkiW4in5pUOb21AdgH29HDwG2mY6iVavsASHRutK747gURR" +
    "lpt3wUJOJk00T9W2N0fVsTE"
  private val jwksJson: String = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"76fd32aec7" +
    "e0f8c190dda8b9dd85e7cf5ad33c43\",\"n\":\"03TVzpSoWDe8iPqvAde1JmmITIHD6JU8Koy10fSUW0u1QO6fle93GxHOHeQmP7FBhLSy5g" +
    "WK23za38kN0KMucYGOjcWOwnO_pTQrCXxFzD-HBy_IiRyRkhuaQXsKvpJbblMEmcfeR4cWlzKt9RKjjXBl5bmIiLrN167iftlR84E\",\"e\":" +
    "\"AQAB\"},{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"317b5931c783031d970c1a2552266215598a9814" +
    "\",\"n\":\"sxAi31Tz53-HtjmVlGpyNEGO8MtL-uvwdKDG__a-gPYE8WGEQQgpBXjjFqmIsfs-yd8YHYw0uCJwAu-ILT1AbhVTZiEEnrLKNTc_" +
    "gPqfveZxnySJCguVx1pWpZ0q9cBMdgvetrbUfRO2Sz1YFgfD7k9BacWwOM-eiFtgrWwOTo8\",\"e\":\"AQAB\"}]}"
  private val clientId: String = "822737555429-evvkd00otqr5gl110nfapisjfoea36jf.apps.googleusercontent.com"
  private val issuer: String = "accounts.google.com"
  private val evaluationTime: Instant = Instant.ofEpochSecond(1431612438L)
  private val subjectValue: String = "116308408314661478132"

  "Googles Too Small Key" should "failed with strict by default" in {
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](idToken)(jwks.verificationPrimitives)(jwks.decryptionPrimitives)
          .map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "Googles Too Small Key" should "succeed with first work around using two pass" in {
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](idToken, JoseConfig(doKeyValidation = false))(
          jwks.verificationPrimitives
        )(jwks.decryptionPrimitives))
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
        _ <- jwtClaims.checkTime(evaluationTime).eLiftET[IO]
        _ <- jwtClaims.requireSubject.eLiftET[IO]
        _ <- jwtClaims.expectedIssuers(issuer).eLiftET[IO]
        _ <- jwtClaims.expectedAudiences(clientId).eLiftET[IO]
      yield
        jwtClaims.subject.contains(subjectValue)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "Googles Too Small Key" should "succeed after they moved to 2048" in {
    // endpoints mentioned were found at https://accounts.google.com/.well-known/openid-config
    // JWKS content from https://www.googleapis.com/oauth2/v3/certs on July 8, 2015
    val jwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"e53139984bd36d2c23055244" +
      "1608cc0b5179487a\",\"n\":\"w5F_3au2fyRLapW4K1g0zT6hjF-co8hjHJWniH3aBOKP45xuSRYXnPrpBHkXM6jFkVHs2pCFAOg6o0tl65" +
      "iRCcf3hOAI6VOIXjMCJqxNap0-j_lJ6Bc6TBKgX3XD96iEI92iaxn_UIVZ_SpPrbPVyRmH0P7B6oDkwFpApviJRtQzv1F6uyh9W_sNnEZrCZD" +
      "cs5lL5Xa_44-EkhVNz8yGZmAz9d04htNU7xElmXKs8fRdospyv380WeaWFoNJpc-3ojgRus26jvPy8Oc-d4M5yqs9mI72-1G0zbGVFI_PfxZR" +
      "L8YdFAIZLg44zGzL2M7pFmagJ7Aj46LUb3p_n9V1NQ\",\"e\":\"AQAB\"},{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig" +
      "\",\"kid\":\"bc8a31927af20860418f6b2231bbfd7ebcc04665\",\"n\":\"ucGr4fFCJYGVUwHYWAtBNclebyhMjALOTUmmAXdMrCIOg" +
      "T8TxBEn5oXCrszWX7RoC37nFqc1GlMorfII19qMwHdC_iskju3Rh-AuHr29zkDpYIuh4lRW0xJ0Xyo2Iw4PlV9qgqPJLfkmE5V-sr5RxZNe0T" +
      "1jyYaOGIJ5nF3WbDkgYW4GNHXhv-5tOwWLThJRtH_n6wtYqsBwqAdVX-EVbkyZvYeOzbiNiop7bDM5Td6ER1oCBC4NZjvjdmnOh8-_x6vB449" +
      "jL5IRAOIIv8NW9dLtQd2DescZOw46HZjWO-zwyhjQeYY87R93yM9yivJdfrjQxydgEs8Ckh03NDATmQ\",\"e\":\"AQAB\"}]}"
    // an ID token from making an openid request to https://accounts.google.com/o/oauth2/v2/auth
    val jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJjOGEzMTkyN2FmMjA4NjA0MThmNmIyMjMxYmJmZDdlYmNjMDQ2NjUifQ.eyJpc3MiOiJhY2" +
      "NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTA5MzM5ODA3NjQ3Nzc3MzkzOTYxIiwiYXpwIjoiMTA3ODQ0OTAyOTY4Ni5hcHBzLmdvb2dsZXV" +
      "zZXJjb250ZW50LmNvbSIsImF1ZCI6IjEwNzg0NDkwMjk2ODYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0MzYzODUzMzYs" +
      "ImV4cCI6MTQzNjM4ODkzNn0.B8jAoYKnsN0Xy62VjBXIrk5B-3ZdbQNt_qzndhlOJXpo4W0C1Q4BvC8YjFc2k6T1qNuehfSrO9xvm-BQGAXRy" +
      "uQSZPpcQOtP2_LR39oYpnBgDwGKxTdJwAHTIoYTti1R1o-sAkMk-dt4lP45RbUXJEKST0RLKe9RdjNKLtcg62wSvVuLwaqRYyIRWK3Tb8aRA3" +
      "Eay8uUe8Llk5qJ-1E1pSOscvlYF6EVNkafKBa4jC5utAu5WwvdDoMFz3ZPOzNnhQsjOdxtnAjN3mI9EWNALUsLrdY54-O0JnVJGywKEnwfeDB" +
      "cUClt_ZBwV-Rl8WMv8TWZRJ8SWywnYi2gaBnaPw"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt)(jwks.verificationPrimitives)(
          jwks.decryptionPrimitives
        ))
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1436388930L)).eLiftET[IO]
        _ <- jwtClaims.requireSubject.eLiftET[IO]
        _ <- jwtClaims.expectedIssuers(issuer).eLiftET[IO]
        // borrowed a bitbucket client id
        _ <- jwtClaims.expectedAudiences("1078449029686.apps.googleusercontent.com").eLiftET[IO]
      yield
        jwtClaims.subject.contains("109339807647777393961")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end GooglesTooSmallKeyFlatSpec
