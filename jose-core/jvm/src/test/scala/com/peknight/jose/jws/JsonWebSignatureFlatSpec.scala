package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.jose.JoseHeader
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.*
import com.peknight.jose.jwk.ops.{AESKeyOps, EllipticCurveKeyOps, RSAKeyOps}
import com.peknight.jose.jwt.JsonWebTokenClaims
import com.peknight.security.provider.Provider
import com.peknight.security.random.SecureRandom
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.{Key, KeyPair}
import java.time.Instant

class JsonWebSignatureFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private val jwtClaims = JsonWebTokenClaims(
    issuer = Some("joe"),
    expirationTime = Some(Instant.ofEpochSecond(1300819380)),
    ext = Some(JsonObject("http://example.com/is_root" -> Json.True))
  )

  def testKey(algorithm: JsonWebAlgorithm, key: Key, provider: Option[Provider] = None): IO[Boolean] =
    testKeys(algorithm, key, key, provider)

  def testKeyPair(algorithm: JsonWebAlgorithm, keyPair: KeyPair, provider: Option[Provider] = None): IO[Boolean] =
    testKeys(algorithm, keyPair.getPrivate, keyPair.getPublic, provider)

  def testKeys(algorithm: JsonWebAlgorithm, signingKey: Key, verificationKey: Key, provider: Option[Provider] = None)
  : IO[Boolean] =
    val eitherT =
      for
        signature <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](JoseHeader.jwtHeader(algorithm),
          jwtClaims, Some(signingKey), provider = provider))
        _ = println(signature)
        verify <- EitherT(signature.verify[IO](Some(verificationKey), provider = provider))
        _ = println(verify)
      yield verify
    eitherT.value.map(_.getOrElse(false))

  "JsonWebSignature" should "succeed with HS256" in {
    val run =
      for
        random <- SecureRandom.getInstanceStrong[IO]
        key <- AESKeyOps.generateKey[IO](256, random)
        res <- testKey(HS256, key)
      yield res
    run.asserting(assert)
  }

  "JsonWebSignature" should "succeed with RS256" in {
    val run =
      for
        keyPair <- RSAKeyOps.keySizeGenerateKeyPair[IO](2048)
        res <- testKeyPair(RS256, keyPair)
      yield res
    run.asserting(assert)
  }

  "JsonWebSignature" should "succeed with PS256" in {
    val run =
      for
        keyPair <- RSAKeyOps.keySizeGenerateKeyPair[IO](2048)
        res <- testKeyPair(PS256, keyPair)
      yield res
    run.asserting(assert)
  }

  "JsonWebSignature" should "succeed with ES256" in {
    val run =
      for
        keyPair <- EllipticCurveKeyOps.paramsGenerateKeyPair[IO](ES256.curve.ecParameterSpec)
        res <- testKeyPair(ES256, keyPair)
      yield res
    run.asserting(assert)
  }

  "JsonWebSignature" should "succeed with none" in {
    val eitherT =
      for
        signature <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](JoseHeader.jwtHeader(none), jwtClaims))
        _ = println(signature)
        verify <- EitherT(signature.verify[IO]())
        _ = println(verify)
      yield verify
    eitherT.value.map(_.getOrElse(false)).asserting(assert)
  }
end JsonWebSignatureFlatSpec
