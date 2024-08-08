package com.peknight.jose.jwk

import cats.Id
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.option.*
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.jose.jwa.ecc.`P-384`
import com.peknight.jose.jwk.JsonWebKey.PublicJsonWebKey
import com.peknight.jose.key.{EllipticCurveKeyOps, RSAKeyOps}
import com.peknight.security.bouncycastle.jce.provider.BouncyCastleProvider
import com.peknight.security.provider.Provider
import com.peknight.security.{SecureRandom, Security}
import org.jose4j.jwk.JsonWebKey.OutputControlLevel
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.{KeyPair, SecureRandom as JSecureRandom}

class JsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  given CanEqual[JsonWebKey, JsonWebKey] = CanEqual.derived

  def testKeyPair(generateKeyPair: (Provider, JSecureRandom) => IO[KeyPair]): IO[Boolean] =
    for
      provider <- BouncyCastleProvider[IO]
      _ <- Security.addProvider[IO](provider)
      secureRandom <- SecureRandom[IO]
      keyPair <- generateKeyPair(BouncyCastleProvider, secureRandom)
      joseJwkEither = JsonWebKey.fromKeyPair(keyPair)
      restoredKeyPair <- joseJwkEither match
        case Right(joseJwk: PublicJsonWebKey) => joseJwk.toKeyPair[IO](Some(BouncyCastleProvider)).map(_.some)
        case _ => IO(None)
      jose4jJwk = org.jose4j.jwk.JsonWebKey.Factory.newJwk(keyPair.getPublic).asInstanceOf[org.jose4j.jwk.PublicJsonWebKey]
      _ = jose4jJwk.setPrivateKey(keyPair.getPrivate)
      jose4jJwkEither = decode[Id, JsonWebKey](jose4jJwk.toJson(OutputControlLevel.INCLUDE_PRIVATE))
    yield
      (joseJwkEither, jose4jJwkEither, restoredKeyPair) match
        case (Right(joseEcJwk), Right(jose4jEcJwk), Some(Right(restored))) =>
          joseEcJwk == jose4jEcJwk &&
            restored.getPublic.equals(keyPair.getPublic) &&
            restored.getPrivate.equals(keyPair.getPrivate)
        case _ => false

  "JsonWebKey" should "succeed with EC" in {
    testKeyPair((provider, random) =>
      EllipticCurveKeyOps.generateKeyPair[IO](`P-384`.ecParameterSpec, Some(provider), Some(random))
    ).asserting(assert)
  }

  "JsonWebKey" should "succeed with RSA" in {
    testKeyPair((provider, random) =>
      RSAKeyOps.generateKeyPair[IO](1024, Some(provider), Some(random))
    ).asserting(assert)
  }
end JsonWebKeyFlatSpec
