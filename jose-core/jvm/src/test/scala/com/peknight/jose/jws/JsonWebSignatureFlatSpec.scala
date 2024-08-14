package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.jose.JoseHeader
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwk.ops.AESKeyOps
import com.peknight.jose.jwt.JsonWebTokenClaims
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

  def test(algorithm: JsonWebAlgorithm, key: Key): IO[Boolean] = test(algorithm, key, key)

  def test(algorithm: JsonWebAlgorithm, keyPair: KeyPair): IO[Boolean] =
    test(algorithm, keyPair.getPrivate, keyPair.getPublic)

  def test(algorithm: JsonWebAlgorithm, signingKey: Key, verificationKey: Key): IO[Boolean] =
    val eitherT =
      for
        signature <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](JoseHeader.jwtHeader(algorithm),
          jwtClaims, Some(signingKey)))
        verify <- EitherT(signature.verify[IO](Some(verificationKey)))
      yield verify
    eitherT.value.map(_.getOrElse(false))

  "JsonWebSignature" should "succeed with HmacSHA2" in {
    val run =
      for
        random <- SecureRandom.getInstanceStrong[IO]
        key <- AESKeyOps.generateKey[IO](256, random)
        res <- test(HS256, key)
      yield res
    run.asserting(assert)
  }
end JsonWebSignatureFlatSpec
