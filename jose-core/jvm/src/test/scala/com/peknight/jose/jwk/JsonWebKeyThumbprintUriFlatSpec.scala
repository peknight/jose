package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebKeyThumbprintUriFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKeyThumbprintUri" should "succeed with RSA from RFC example 3" in {
    val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
      "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0" +
      "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC" +
      "ur-kEgU8awapJzKnqDKgw"
    val jwk =
      s"""
         |{
         | "kty": "RSA",
         | "n": "$n",
         | "e": "AQAB",
         | "alg": "RS256",
         | "kid": "2011-04-29"
         |}
      """.stripMargin
    val expectedThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with oct" in {
    val jwk = """{"k":"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg","kty":"oct"}"""
    val expectedThumbprint = "7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with ec 1" in {
    val jwk = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\",\"y\":\"EldWz" +
      "_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"}"
    val expectedThumbprint = "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with ec 2" in {
    val jwk = "{\"kty\":\"EC\",\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\",\"crv\":\"P-256\",\"x\":\"CEuRL" +
      "UISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"}"
    val expectedThumbprint = "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with ec from nimb" in {
    val jwk = "{\"crv\":\"P-256\", \"kty\":\"EC\", \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", \"x\":\"MK" +
      "BCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"}"
    val expectedThumbprint = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with oct from nimb" in {
    val jwk = """{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"""
    val expectedThumbprint = "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with jose wg list test vector(0)" in {
    // https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
    // ... https://mailarchive.ietf.org/arch/msg/jose/nxct2sTGJvHxtOtofmUA8bMe6B0
    val jwk = """{"kty":"oct", "k":"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg"}"""
    val expectedThumbprint = "7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with jose wg list test vector(1)" in {
    val jwk = "{\"kty\":\"EC\",\n \"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\",\n \"y\":\"EldWz_iXSK3l_S7n4" +
      "w_t3baxos7o9yqX0IjzG959vHc\",\n \"crv\":\"P-256\"}"
    val expectedThumbprint = "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with jose wg list test vector(2)" in {
    val jwk = "{\"kty\":\"EC\",\n \"x\":\"Aeq3uMrb3iCQEt0PzSeZMmrmYhsKP5DM1oMP6LQzTFQY9-F3Ab45xiK4AJxltXEI-87g3gRwId" +
      "88hTyHgq180JDt\",\n \"y\":\"ARA0lIlrZMEzaXyXE4hjEkc50y_JON3qL7HSae9VuWpOv_2kit8p3pyJBiRb468_U5ztLT7FvDvtimyS4" +
      "2trhDTu\",\n \"crv\":\"P-521\"}"
    val expectedThumbprint = "rz4Ohmpxg-UOWIWqWKHlOe0bHSjNUFlHW5vwG_M7qYg"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with jose wg list test vector(3)" in {
    val jwk = "{\"kty\":\"EC\",\n \"x\":\"2jCG5DmKUql9YPn7F2C-0ljWEbj8O8-vn5Ih1k7Wzb-y3NpBLiG1BiRa392b1kcQ\",\n \"y" +
      "\":\"7Ragi9rT-5tSzaMbJlH_EIJl6rNFfj4V4RyFM5U2z4j1hesX5JXa8dWOsE-5wPIl\",\n \"crv\":\"P-384\"}"
    val expectedThumbprint = "vZtaWIw-zw95JNzzURg1YB7mWNLlm44YZDZzhrPNetM"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  "JsonWebKeyThumbprintUri" should "succeed with jose wg list test vector(4)" in {
    val jwk = """{"kty":"oct","k":"NGbwp1rC4n85A1SaNxoHow"}"""
    val expectedThumbprint = "5_qb56G0OJDw-lb5mkDaWS4MwuY0fatkn9LkNqUHqMk"
    testJwkThumbprintUri(jwk, expectedThumbprint)
  }

  def testJwkThumbprintUri(jwkText: String, expectedThumbprint: String)
  : IO[Assertion] =
    val run =
      for
        jsonWebKey <- decode[Id, JsonWebKey](jwkText).eLiftET[IO]
        uri <- EitherT(jsonWebKey.calculateThumbprintUri[IO]())
      yield
        uri.renderString == s"urn:ietf:params:oauth:jwk-thumbprint:sha-256:$expectedThumbprint"
    run.value.asserting(value => assert(value.getOrElse(false)))
end JsonWebKeyThumbprintUriFlatSpec
