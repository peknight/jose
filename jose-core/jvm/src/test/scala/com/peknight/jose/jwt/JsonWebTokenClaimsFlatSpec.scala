package com.peknight.jose.jwt

import cats.Id
import cats.syntax.eq.*
import com.peknight.cats.instances.time.instant.given
import cats.syntax.order.*
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.commons.time.syntax.temporal.{minus, plus}
import com.peknight.cats.effect.ext.Clock

import scala.concurrent.duration.*
import com.peknight.jose.jwx.encodeToJson
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import io.circe.parser.decode as circeDecode
import com.peknight.jose.jwa.encryption.randomBytes
import io.circe.JsonObject
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class JsonWebTokenClaimsFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
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
    assert(decode[Id, JsonWebTokenClaims](s"""{"jti":"$jwtId"}""").exists(_.jwtID.contains(JwtId(jwtId))))
  }
  "JsonWebTokenClaims" should "failed with bad jwt id" in {
    assert(decode[Id, JsonWebTokenClaims]("""{"jti":["nope", "not", "good"]}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with generate and get jwt" in {
    randomBytes[IO](16)
      .map(bytes => JsonWebTokenClaims(jwtID = Some(JwtId(Base64UrlNoPad.fromByteVector(bytes).value))))
      .asserting(jwtClaims => assert(
        jwtClaims.jwtID.exists(_.value.length == 22) &&
          jwtClaims.copy(jwtID = Some(JwtId("igotyourjtirighthere"))).jwtID.exists(_.value == "igotyourjtirighthere")
      ))
  }
  "JsonWebTokenClaims" should "succeed with get null expiration time" in {
    assert(decode[Id, JsonWebTokenClaims](s"""{"right":123456781}""").exists(_.expirationTime.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get expiration time" in {
    val exp = 1418823169
    assert(decode[Id, JsonWebTokenClaims](s"""{"exp":$exp}""").exists(_.expirationTime.exists(_.getEpochSecond == exp)))
  }
  "JsonWebTokenClaims" should "failed with get bad expiration time" in {
    assert(decode[Id, JsonWebTokenClaims](s"""{"exp":"nope"}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with get null not before" in {
    assert(decode[Id, JsonWebTokenClaims](s"""{"right":123456781}""").exists(_.notBefore.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get not before" in {
    val nbf = 1418823169
    assert(decode[Id, JsonWebTokenClaims](s"""{"nbf":$nbf}""").exists(_.notBefore.exists(_.getEpochSecond == nbf)))
  }
  "JsonWebTokenClaims" should "failed with get bad not before" in {
    assert(decode[Id, JsonWebTokenClaims](s"""{"nbf":["nope", "not", "good"]}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with get null issued at" in {
    assert(decode[Id, JsonWebTokenClaims](s"""{"right":123456781, "wrong":123452781}""").exists(_.issuedAt.isEmpty))
  }
  "JsonWebTokenClaims" should "succeed with get issued at" in {
    val iat = 1418823169
    assert(decode[Id, JsonWebTokenClaims](s"""{"iat":$iat}""").exists(_.issuedAt.exists(_.getEpochSecond == iat)))
  }
  "JsonWebTokenClaims" should "failed with get bad issued at" in {
    assert(decode[Id, JsonWebTokenClaims](s"""{"iat":"not"}""").isLeft)
  }
  "JsonWebTokenClaims" should "succeed with basic create" in {
    val json = encodeToJson(JsonWebTokenClaims(
      issuer = Some("issuer"),
      subject = Some("subject"),
      audience = Some(Set("audience")),
      expirationTime = Some(Instant.ofEpochSecond(231458800)),
      notBefore = Some(Instant.ofEpochSecond(231459600)),
      issuedAt = Some(Instant.ofEpochSecond(231459000)),
      jwtID = Some(JwtId("id"))
    ))
    assert(json.contains(""""iss":"issuer""""))
    assert(json.contains(""""aud":"audience""""))
    assert(json.contains(""""sub":"subject""""))
    assert(json.contains(""""jti":"id""""))
    assert(json.contains(""""exp":231458800"""))
    assert(json.contains(""""iat":231459000"""))
    assert(json.contains(""""nbf":231459600"""))
  }

  "JsonWebTokenClaims" should "succeed with testing audience" in {
    assert(encodeToJson(JsonWebTokenClaims(audience = Some(Set("audience")))).contains(""""aud":"audience""""))
    assert(encodeToJson(JsonWebTokenClaims(audience = Some(Set("audience1", "audience2", "outlier"))))
      .contains(""""aud":["audience1","audience2","outlier"]"""))
    assert(encodeToJson(JsonWebTokenClaims(audience = Some(Set("one", "two", "three"))))
      .contains(""""aud":["one","two","three"]"""))
    assert(encodeToJson(JsonWebTokenClaims()) == "{}")
  }

  "JsonWebTokenClaims" should "succeed with create with helpers" in {
    val run =
      for
        bytes <- randomBytes[IO](16)
        now <- Clock.realTimeInstant[IO]
      yield
        (encodeToJson(JsonWebTokenClaims(
          issuer = Some("issuer"),
          subject = Some("subject"),
          audience = Some(Set("audience")),
          expirationTime = Some(now.plus(10.minutes)),
          notBefore = Some(now.minus(5.minutes)),
          issuedAt = Some(now),
          jwtID = Some(JwtId(Base64UrlNoPad.fromByteVector(bytes).value))
        )), now)
    run.asserting((json, now) => assert(
      json.contains(""""iss":"issuer"""") &&
        json.contains(""""aud":"audience"""") &&
        json.contains(""""sub":"subject"""") &&
        json.contains(""""jti":"""") &&
        json.contains(""""exp":""") &&
        json.contains(""""iat":""") &&
        json.contains(""""nbf":""") &&
        decode[Id, JsonWebTokenClaims](json).exists(
          jwtClaims => jwtClaims.jwtID.exists(_.value.length == 22) &&
            jwtClaims.notBefore.exists(nbf => nbf <= now.minus(300000.millis) && nbf > now.minus(302000.millis)) &&
            jwtClaims.issuedAt.exists(iat => iat < now.plus(100.millis) && now.minus(2000.millis) < iat) &&
            jwtClaims.expirationTime.exists(exp => exp > now.plus(598000.millis) && exp < now.plus(600000.millis))
        )
    ))
  }

  "JsonWebTokenClaims" should "succeed with set expiration time in the future part of minute" in {
    Clock.realTimeInstant[IO].asserting { now =>
      val json = encodeToJson(JsonWebTokenClaims(expirationTime = Some(now.plus(0.167.minutes))))
      assert(decode[Id, JsonWebTokenClaims](json).exists(jwtClaims => jwtClaims.expirationTime.exists(exp =>
        now < exp && now.plus(9.seconds) < exp && now.plus(11.seconds) >= exp
      )))
    }
  }

  "JsonWebTokenClaims" should "succeed with get claims map" in {
    val json = "{\"sub\":\"subject\",\"aud\":\"audience\",\"iss\":\"issuer\",\"jti\":\"mz3uxaCcLmQ2cwAV3oJxEQ\",\"ex" +
      "p\":1418906607,\"email\":\"user@somewhere.io\", \"name\":\"Joe User\", \"someclaim\":\"yup\"}"
    assert(decode[Id, JsonWebTokenClaims](json).flatMap(jwtClaims => circeDecode[JsonObject](encodeToJson(jwtClaims)))
      .exists(jsonObject =>
        jsonObject.filterKeys(key => !JsonWebTokenClaims.initialRegisteredClaimNames.contains(key)).size == 3 &&
          jsonObject.size == 8 &&
          jsonObject.filterKeys(key => key != JsonWebTokenClaims.audienceLabel).size == 7
      ))
  }

  "JsonWebTokenClaims" should "succeed with decodeExt" in {
    case class Claims(`string`: String, array: List[String])
    import com.peknight.codec.configuration.given
    import com.peknight.codec.circe.sum.jsonType.given
    val json = """{"string":"a value","array":["one","two","three"]}"""
    assert(decode[Id, JsonWebTokenClaims](json).flatMap(jwtClaims => jwtClaims.decodeExt[Id, Claims])
      .exists(claims => claims.`string` == "a value" && claims.array === List("one", "two", "three")))
  }

  "JsonWebTokenClaims" should "succeed with simple claims example from draft" in {
    import com.peknight.codec.configuration.given
    import com.peknight.codec.circe.sum.jsonType.given
    val json = """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    assert(decode[Id, JsonWebTokenClaims](json).exists(jwtClaims =>
      jwtClaims.issuer.contains("joe") &&
        jwtClaims.expirationTime.exists(_.compareTo(Instant.ofEpochSecond(1300819380)) == 0)
        jwtClaims.decodeExt[Id, Map[String, Boolean]].exists(ext => ext.getOrElse("http://example.com/is_root", false))
    ))
  }

  "JsonWebTokenClaims" should "succeed with non integer numeric dates" in {
    println(decode[Id, JsonWebTokenClaims]("{\"sub\":\"brain.d.campbell\",\"nbf\":1430602000.173,\"iat\":1430602060.5" +
      ",\"exp\":1430602600.77}").left.map(_.message))
    assert(decode[Id, JsonWebTokenClaims]("{\"sub\":\"brain.d.campbell\",\"nbf\":1430602000.173,\"iat\":1430602060.5" +
      ",\"exp\":1430602600.77}").exists(jwtClaims =>
      jwtClaims.expirationTime.exists(_.compareTo(Instant.ofEpochSecond(1430602600)) == 0) &&
        jwtClaims.issuedAt.exists(_.compareTo(Instant.ofEpochSecond(1430602060)) == 0) &&
        jwtClaims.notBefore.exists(_.compareTo(Instant.ofEpochSecond(1430602000)) == 0)
    ))
  }
end JsonWebTokenClaimsFlatSpec
