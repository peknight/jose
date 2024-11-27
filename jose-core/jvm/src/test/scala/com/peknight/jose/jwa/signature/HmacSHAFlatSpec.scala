package com.peknight.jose.jwa.signature

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jws.JsonWebSignatureTestOps.{testBadKeyOnSign, testBadKeyOnVerify}
import com.peknight.jose.jws.{JsonWebSignature, JsonWebSignatureTestOps}
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.mac.Hmac
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import javax.crypto.spec.SecretKeySpec

class HmacSHAFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  val key1: SecretKeySpec = Hmac.secretKeySpec(ByteVector(-41, -1, 60, 1, 1, 45, -92, -114, 8, -1, -60, 7, 54, -16, 16,
    14, -20, -85, 56, 103, 4, 10, -56, 120, 37, -48, 6, 9, 110, -96, 27, -4, 41, -99, 60, 91, 49, 70, -99, -14, -108,
    -81, 60, 37, 104, -116, 106, 104, -2, -95, 56, 103, 64, 10, -56, 120, 37, -48, 6, 9, 110, -96, 27, -4))
  val key2: SecretKeySpec = Hmac.secretKeySpec(ByteVector(-67, 34, -45, 50, 13, 84, -79, 124, -16, -44, 26, -39, 4, -1,
    26, 9, 38, 78, -107, 39, -81, 75, -18, 38, 96, 34, 13, 79, -73, 62, -60, 52, 71, -99, 60, 91, 124, 70, -9, -14,
    -108, -104, 6, 7, 104, -116, 6, 64, -2, -95, 56, 103, 64, 10, -56, 120, 37, -48, 6, 9, 110, -92, 27, -4))

  "HmacSHA" should "succeed with HS256 A" in {
    testBasicRoundTrip("some content that is the payload", HS256)
  }

  "HmacSHA" should "succeed with HS256 B" in {
    val payload = "{\"iss\":\"https://jwt-idp.example.com\",\"prn\":\"mailto:mike@example.com\",\"aud\":\"https://jw" +
      "t-rp.example.net\",\"iat\":1300815780,\"exp\":1300819380,\"http://claims.example.com/member\":true}"
    testBasicRoundTrip(payload, HS256)
  }

  "HmacSHA" should "succeed with HS384 A" in {
    testBasicRoundTrip("Looking good, Billy Ray!", HS384)
  }

  "HmacSHA" should "succeed with HS384 B" in {
    testBasicRoundTrip("""{"meh":"meh"}""", HS384)
  }

  "HmacSHA" should "succeed with HS512 A" in {
    testBasicRoundTrip("Feeling good, Louis!", HS512)
  }

  "HmacSHA" should "succeed with HS512 B" in {
    testBasicRoundTrip("""{"meh":"mehvalue"}""", HS512)
  }

  private def testBasicRoundTrip(payload: String, jwsAlgo: JWSAlgorithm): IO[Assertion] =
    JsonWebSignatureTestOps.testBasicRoundTrip(payload, jwsAlgo, key1, key1, key2, key2)
      .value.asserting(value => assert(value.isRight))

  "HmacSHA" should "failed with min key size 256 for sign" in {
    testBadKeyOnSign(HS256, Some(Hmac.secretKeySpec(ByteVector(0)))).asserting(assert)
  }

  "HmacSHA" should "failed with min key size 256 for sign 2" in {
    testBadKeyOnSign(HS256, Some(Hmac.secretKeySpec(ByteVector.fill(31)(0)))).asserting(assert)
  }

  "HmacSHA" should "failed with min key size 384 for sign" in {
    testBadKeyOnSign(HS384, Some(Hmac.secretKeySpec(ByteVector.fill(47)(0)))).asserting(assert)
  }

  "HmacSHA" should "failed with min key size 512 for sign" in {
    testBadKeyOnSign(HS512, Some(Hmac.secretKeySpec(ByteVector.fill(63)(0)))).asserting(assert)
  }

  "HmacSHA" should "failed with min key size 256 for verify" in {
    val compact = "eyJhbGciOiJIUzI1NiJ9.c29tZSBjb250ZW50IHRoYXQgaXMgdGhlIHBheWxvYWQ.qGO7O7W2ECVl6uO7lfsXDgEF-EUEti0i" +
      "-a_AimulIRA"
    testBadKeyOnVerify(compact, Some(Hmac.secretKeySpec(ByteVector.fill(31)(0))))
      .value.asserting(value => assert(value.isRight))
  }

  "HmacSHA" should "failed with min key size 384 for verify" in {
    val compact = "eyJhbGciOiJIUzM4NCJ9.eyJtZWgiOiJtZWgifQ.fptKQJmGN3fBP_FiQzdAGdmx-Q5iWjQvJrLfdmFnebxbQuzOmzejBrzYh" +
      "4MyS01a"
    testBadKeyOnVerify(compact, Some(Hmac.secretKeySpec(ByteVector.fill(47)(0))))
      .value.asserting(value => assert(value.isRight))
  }

  "HmacSHA" should "failed with min key size 512 for verify" in {
    val compact = "eyJhbGciOiJIUzUxMiJ9.eyJtZWgiOiJtZWh2YWx1ZSJ9.NeB669dYkPmqgLqgd_sVqwIfCvb4XN-K67gpMJR93wfw_DylpxB" +
      "1ell2opHM-E5P9jNKE2GYxTxwcI68Z2CTxw"
    testBadKeyOnVerify(compact, Some(Hmac.secretKeySpec(ByteVector.fill(63)(0))))
      .value.asserting(value => assert(value.isRight))
  }

  "HmacSHA" should "failed with validate key switch" in {
    val key = Hmac.secretKeySpec(ByteVector(1, 2, 5, -9, 99, -99, 0, 40, 21))
    val run =
      for
        jws <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(HS256)), "whatever", Some(key), false))
        cs <- jws.compact.eLiftET[IO]
        _ <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(HS256)), "whatever", Some(key)).map(_.swap.asError))
      yield
        cs.nonEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end HmacSHAFlatSpec
