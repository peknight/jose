package com.peknight.jose.jwk

import cats.Id
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.option.*
import com.peknight.codec.circe.parser.decode
import com.peknight.jose.jwa.ecc.`P-384`
import com.peknight.jose.jwk.JsonWebKey.{AsymmetricJsonWebKey, OctetSequenceJsonWebKey}
import com.peknight.security.Security
import com.peknight.security.bouncycastle.jce.provider.BouncyCastleProvider
import com.peknight.security.cipher.{AES, RSA}
import com.peknight.security.provider.Provider
import com.peknight.security.random.SecureRandom
import com.peknight.validation.std.either.typed
import org.jose4j.jwk.JsonWebKey.OutputControlLevel
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.{KeyPair, SecureRandom as JSecureRandom}

class JsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  given CanEqual[JsonWebKey, JsonWebKey] = CanEqual.derived

  def testKeyPair(generateKeyPair: (JSecureRandom, Provider) => IO[KeyPair]): IO[Boolean] =
    for
      provider <- BouncyCastleProvider[IO]
      _ <- Security.addProvider[IO](provider)
      secureRandom <- SecureRandom[IO]
      keyPair <- generateKeyPair(secureRandom, BouncyCastleProvider)
      joseJwkEither = JsonWebKey.fromKeyPair(keyPair)
      checkResult <- joseJwkEither match
        case Right(joseJwk: AsymmetricJsonWebKey) => joseJwk.checkJsonWebKey[IO](Some(BouncyCastleProvider)).map(_.isRight)
        case _ => IO(false)
      restoredKeyPair <- joseJwkEither match
        case Right(joseJwk: AsymmetricJsonWebKey) => joseJwk.keyPair[IO](Some(BouncyCastleProvider)).map(_.some)
        case _ => IO(None)
      jose4jJwk = org.jose4j.jwk.JsonWebKey.Factory.newJwk(keyPair.getPublic).asInstanceOf[org.jose4j.jwk.PublicJsonWebKey]
      _ = jose4jJwk.setPrivateKey(keyPair.getPrivate)
      jose4jJwkEither = decode[Id, JsonWebKey](jose4jJwk.toJson(OutputControlLevel.INCLUDE_PRIVATE))
    yield
      (joseJwkEither, jose4jJwkEither, restoredKeyPair, checkResult) match
        case (Right(joseJwk), Right(jose4jJwk), Some(Right(restored)), true) =>
          joseJwk == jose4jJwk &&
            restored.getPublic.equals(keyPair.getPublic) &&
            restored.getPrivate.equals(keyPair.getPrivate)
        case _ => false

  "JsonWebKey" should "succeed with EC" in {
    testKeyPair((random, provider) =>
      `P-384`.generateKeyPair[IO](Some(random), Some(provider))
    ).asserting(assert)
  }

  "JsonWebKey" should "succeed with RSA" in {
    testKeyPair((random, provider) =>
      RSA.keySizeGenerateKeyPair[IO](1024, Some(random), Some(provider))
    ).asserting(assert)
  }

  "JsonWebKey" should "succeed with AES" in {
    val run =
      for
        key <- AES.keySizeGenerateKey[IO](256)
        joseJwkEither = JsonWebKey.fromKey(key)
        restoredKey = joseJwkEither.flatMap(typed[OctetSequenceJsonWebKey]).map(_.toKey).toOption
        jose4jJwk = org.jose4j.jwk.JsonWebKey.Factory.newJwk(key).asInstanceOf[org.jose4j.jwk.OctetSequenceJsonWebKey]
        jose4jJwkEither = decode[Id, JsonWebKey](jose4jJwk.toJson(OutputControlLevel.INCLUDE_PRIVATE))
      yield
        (joseJwkEither, jose4jJwkEither, restoredKey) match
          case (Right(joseJwk), Right(jose4jJwk), Some(Right(restored))) =>
            joseJwk == jose4jJwk && restored.equals(key)
          case _ => false
    run.asserting(assert)
  }
end JsonWebKeyFlatSpec
