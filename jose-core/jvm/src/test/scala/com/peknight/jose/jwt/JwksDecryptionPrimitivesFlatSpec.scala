package com.peknight.jose.jwt

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.std.UUIDGen
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.ecc.`P-256`
import com.peknight.jose.jwa.encryption.{`A128CBC-HS256`, `ECDH-ES+A128KW`}
import com.peknight.jose.jwa.signature.ES256
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwk.{JsonWebKey, JsonWebKeySet, KeyId}
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader}
import com.peknight.security.key.agreement.X25519
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class JwksDecryptionPrimitivesFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JwksDecryptionPrimitives" should "succeed with resolve okp key" in {
    val claims = JsonWebTokenClaims(subject = Some("example with OKP encryption key"))
    val run =
      for
        ec256KeyPair <- EitherT(`P-256`.generateKeyPair[IO]().asError)
        ec256UUID <- EitherT(UUIDGen.randomString[IO].asError)
        signingKey <- JsonWebKey.fromKeyPair(ec256KeyPair, keyID = Some(KeyId(ec256UUID))).eLiftET[IO]
        jws <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](JoseHeader(Some(ES256),
          keyID = signingKey.keyID), claims, Some(ec256KeyPair.getPrivate)))
        signed <- jws.compact.eLiftET[IO]
        x25519KeyPair1 <- EitherT(X25519.generateKeyPair[IO]().asError)
        x25519UUID1 <- EitherT(UUIDGen.randomString[IO].asError)
        encryptionKey1 <- JsonWebKey.fromKeyPair(x25519KeyPair1, keyID = Some(KeyId(x25519UUID1))).eLiftET[IO]
        x25519KeyPair2 <- EitherT(X25519.generateKeyPair[IO]().asError)
        encryptionKey2 <- JsonWebKey.fromKeyPair(x25519KeyPair2).eLiftET[IO]
        x25519KeyPair3 <- EitherT(X25519.generateKeyPair[IO]().asError)
        x25519UUID3 <- EitherT(UUIDGen.randomString[IO].asError)
        encryptionKey3 <- JsonWebKey.fromKeyPair(x25519KeyPair3, keyID = Some(KeyId(x25519UUID3))).eLiftET[IO]
        dhKeys = List(encryptionKey1, encryptionKey2, encryptionKey3)
        jwe <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(`ECDH-ES+A128KW`), Some(`A128CBC-HS256`),
          keyID = encryptionKey3.keyID, contentType = Some(JsonWebToken.`type`)), signed, x25519KeyPair3.getPublic))
        encrypted <- jwe.compact.eLiftET[IO]
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](encrypted)(
          VerificationPrimitive.verificationKey(Some(ec256KeyPair.getPublic))
        )(JsonWebKeySet(dhKeys).decryptionPrimitives))
      yield
        jwtClaims.subject.contains("example with OKP encryption key")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JwksDecryptionPrimitives" should "succeed with symmetric keys with dir" in {
    val json1 = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"SGfpdt9Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"},{" +
      "\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"Fvlp7BLzRr-a9pOKK7BA25om7u6cY2o9Lz6--UAFWXw\"},{\"kty\":\"oct\",\"ki" +
      "d\":\"tres\",\"k\":\"izcqzDJd6-7rP5pnldgK-jcDjT6xXdo3bIjwgeWAYEc\"}]}"
    val json2 = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"SGfpdt9Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"}," +
      "{\"kty\":\"oct\",\"kid\":\"two\",\"k\":\"izcqzDJd6-7rP5pnldgK-jcDjT6xXdo3bIjwgeWAYEc\"}]}"
    val jwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9..JruwzL7TaQ1Fub8Hw6yYmQ.b4B9F3kerVHv" +
      "yGB5zb40lkTqxulLbMhwFi-qvPfFwwbuyPVPf5s7TeT3i3MLRs0-l_1hP5bPxIEEnOEOBbqTGwO1TWuBn_lQsR8XpQRp6t4H0eaXZsnBqOa3M" +
      "eEtmGpo.Hzbvc--4g2nqIaYoYkc2pQ"
    // bad tag
    val badJwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9..JruwzL7TaQ1Fub8Hw6yYmQ.b4B9F3ker" +
      "VHvyGB5zb40lkTqxulLbMhwFi-qvPfFwwbuyPVPf5s7TeT3i3MLRs0-l_1hP5bPxIEEnOEOBbqTGwO1TWuBn_lQsR8XpQRp6t4H0eaXZsnBqO" +
      "a3MeEtmGpo.Hzbvc__4g2nqIaYoYkc___"
    val run =
      for
        jsonWebKeySet1 <- decode[Id, JsonWebKeySet](json1).eLiftET[IO]
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireSignature = false))(
          jsonWebKeySet1.verificationPrimitives
        )(jsonWebKeySet1.decryptionPrimitives))
        _ <- jwtClaims1.checkTime(Instant.ofEpochSecond(1424015558L)).eLiftET[IO]
        _ <- jwtClaims1.requireExpirationTime.eLiftET[IO]
        _ <- jwtClaims1.expectedIssuers("from").eLiftET[IO]
        _ <- jwtClaims1.expectedAudiences("to").eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](badJwt, JoseConfiguration(requireSignature = false))(
          jsonWebKeySet1.verificationPrimitives
        )(jsonWebKeySet1.decryptionPrimitives).map(_.swap.asError))
        jsonWebKeySet2 <- decode[Id, JsonWebKeySet](json2).eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireSignature = false))(
          jsonWebKeySet2.verificationPrimitives
        )(jsonWebKeySet2.decryptionPrimitives).map(_.swap.asError))
      yield
        nested1.length == 1 && jwtClaims1.subject.contains("Scott Tomilson, not Tomlinson")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JwksDecryptionPrimitives" should "succeed with symmetric keys with AES Wrap" in {
    val json = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"1one\",\"k\":\"_-cqzgJ-_aeZkppR2JCOlx\"},{\"kty\":\"oct\",\"ki" +
      "d\":\"deux\",\"k\":\"mF2rZpj_Fbeal5FRz0c0Lw\"},{\"kty\":\"oct\",\"kid\":\"tres\",\"k\":\"ad2-dGiApcezx9310j4o" +
      "7W\"}]}"
    val jwt = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9.UHa0kaUhz8QDHE_CVfpeC-ebzXapjJrQ" +
      "5Lk4r8XvK1J5WD32UeZ3_A.3pPAmmVX_elO_9lgfJJXiA.8pNNdQ_BsTwFicdrCevByA4i7KAzb__qF6z6olEQ3M8HayMAwOJoeF0yhnkM0Jc" +
      "ydcCiULRE_i8USvpXWiktBhIJ79nDlqHxK09JB6YGnkpBMZgAmWf1NJFmTlF4vRs6.3_UixCVYQsUablSjTX8v2A"
    val run =
      for
        jsonWebKeySet <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireSignature = false))(
          jsonWebKeySet.verificationPrimitives
        )(jsonWebKeySet.decryptionPrimitives))
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1424026062L)).eLiftET[IO]
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
        _ <- jwtClaims.expectedIssuers("from").eLiftET[IO]
        _ <- jwtClaims.expectedAudiences("to").eLiftET[IO]
      yield
        nested.length == 1 && jwtClaims.subject.contains("Scott Tomilson, not Tomlinson")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JwksDecryptionPrimitivesFlatSpec
