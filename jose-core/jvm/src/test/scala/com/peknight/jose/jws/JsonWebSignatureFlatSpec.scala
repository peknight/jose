package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.either.*
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.*
import com.peknight.jose.jwk.ops.{AESKeyOps, RSAKeyOps}
import com.peknight.jose.jwt.JsonWebTokenClaims
import com.peknight.jose.{JoseHeader, jwtType}
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

  def testKey(algorithm: JsonWebAlgorithm, key: Key): IO[Boolean] =
    testKeys(algorithm, key, key)

  def testKeyPair(algorithm: JsonWebAlgorithm, keyPair: KeyPair): IO[Boolean] =
    testKeys(algorithm, keyPair.getPrivate, keyPair.getPublic)

  def testKeys(algorithm: JsonWebAlgorithm, signingKey: Key, verificationKey: Key): IO[Boolean] =
    val eitherT =
      for
        signature <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](JoseHeader.jwtHeader(algorithm),
          jwtClaims, Some(signingKey)))
        _ = println(signature.compact)
        verify <- EitherT(signature.verify[IO](Some(verificationKey)))
        _ = println(verify)
        jose4jSignature <- EitherT(signWithJose4j(signature, signingKey).map(_.asRight))
        _ = println(jose4jSignature)
      yield verify && signature.signature.value == jose4jSignature
    eitherT.value.map(_.getOrElse(false))

  private def signWithJose4j(signature: JsonWebSignature, key: Key): IO[String] = IO {
    val jose4jJws = new org.jose4j.jws.JsonWebSignature()
    signature.getUnprotectedHeader.toOption.flatMap(_.algorithm).map(_.algorithm).foreach(jose4jJws.setAlgorithmHeaderValue)
    jose4jJws.setHeader("typ", jwtType)
    signature.decodePayload.map(_.toArray).foreach(jose4jJws.setPayloadBytes)
    jose4jJws.setKey(key)
    jose4jJws.sign()
    println(jose4jJws.getCompactSerialization)
    jose4jJws.getEncodedSignature
  }

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

  // "JsonWebSignature" should "succeed with ES256" in {
  //   val run =
  //     for
  //       keyPair <- EllipticCurveKeyOps.paramsGenerateKeyPair[IO](ES256.curve.ecParameterSpec)
  //       res <- testKeyPair(ES256, keyPair)
  //     yield res.map(_._2).getOrElse(false)
  //   run.asserting(assert)
  // }

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
