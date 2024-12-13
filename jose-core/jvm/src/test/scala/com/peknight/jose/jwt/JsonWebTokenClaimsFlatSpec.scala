package com.peknight.jose.jwt

import cats.Id
import com.peknight.codec.circe.parser.decode
import org.scalatest.flatspec.AnyFlatSpec

class JsonWebTokenClaimsFlatSpec extends AnyFlatSpec:
  "JsonWebTokenClaims" should "failed with get bad issuer" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"iss":{"name":"value"}}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with get null issuer" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"exp":123456781}""").exists(_.issuer.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get issuer" in {
    val issuer = "https://idp.example.com"
    assert(decode[Id, JsonWebTokenClaims](s"""{"iss":"$issuer"}""").exists(_.issuer.contains(issuer)))
  }
  "JsonWebTokenClaims" should "succeed with get audience with no audience" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"iss":"some-issuer"}""").exists(claims => claims.audience.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get audience single in array" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"aud":["one"]}""").exists(
      claims => claims.audience.exists(audience => audience.size == 1 && audience.contains("one"))
    ))
  }
  "JsonWebTokenClaims" should "succeed with get audience single value" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"aud":"one"}""").exists(
      claims => claims.audience.exists(audience => audience.size == 1 && audience.contains("one"))
    ))
  }
  "JsonWebTokenClaims" should "succeed with get audience multiple in array" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"aud":["one","two","three"]}""").exists(
      claims => claims.audience.exists(audience => audience.size == 3 &&
        audience.contains("one") && audience.contains("two") && audience.contains("three"))
    ))
  }
  "JsonWebTokenClaims" should "succeed with get audience array" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"aud":[]}""").exists(claims => claims.audience.exists(_.isEmpty)))
  }
  "JsonWebTokenClaims" should "failed with bad audience 1" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"aud":1996}""").isLeft)
  }
  "JsonWebTokenClaims" should "failed with bad audience 2" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"aud":["value", "other", 2, "value"]}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with get null subject" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"exp":123456781}""").exists(_.subject.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get subject" in {
    val subject = "subject@example.com"
    assert(decode[Id, JsonWebTokenClaims](s"""{"sub":"$subject"}""").exists(_.subject.contains(subject)))
  }
  "JsonWebTokenClaims" should "failed with bad subject" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"sub":["nope", "not", "good"]}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with get null jwt id" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"whatever":123456781}""").exists(_.jwtID.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get jwt id" in {
    val jwtId = "Xk9c2inNN8fFs60epZil3"
    assert(decode[Id, JsonWebTokenClaims](s"""{"jti":"$jwtId"}""").exists(_.jwtID.contains(jwtId)))
  }
  "JsonWebTokenClaims" should "failed with bad jwt id" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"jti":["nope", "not", "good"]}""").isLeft)
  }
end JsonWebTokenClaimsFlatSpec
