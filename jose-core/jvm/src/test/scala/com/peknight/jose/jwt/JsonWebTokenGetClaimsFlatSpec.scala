package com.peknight.jose.jwt

import cats.Id
import cats.data.EitherT
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.effect.{Clock, IO}
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.commons.time.syntax.temporal.minus
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.RS256
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jwk.*
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader}
import com.peknight.security.cipher.RSA
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant
import scala.concurrent.duration.*

class JsonWebTokenGetClaimsFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebToken getClaims" should "succeed with jwt 61 example unsecured jwt" in {
    // an Example Unsecured JWT from https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-6.1
    val jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb" +
      "290Ijp0cnVlfQ."
    val run =
      for
        (jwtClaims, _) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireSignature = false,
          skipSignatureVerification = true))(VerificationPrimitive.defaultVerificationPrimitivesF)(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims.expectedIssuers("joe").eLiftET[IO]
        (jwtClaims2, _) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireSignature = false))(
          VerificationPrimitive.verificationKey[IO]()
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims2.expectedIssuers("joe").eLiftET[IO]
        _ <- jwtClaims2.requireExpirationTime.eLiftET[IO]
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1300819343L)).eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.verificationKey[IO]()
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
        key <- EitherT(appendixA1.toKey[IO]())
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.verificationKey[IO](Some(key))
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
      yield
        jwtClaims.expirationTime.contains(Instant.ofEpochSecond(1300819380L)) &&
          jwtClaims.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false) &&
          jwtClaims2.expirationTime.contains(Instant.ofEpochSecond(1300819380L)) &&
          jwtClaims2.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false) &&
          jwtClaims2.ext("no-such-claim").isEmpty && jwtClaims2.ext("no way jose").isEmpty &&
          jwtClaims2.ext("nope").isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with jwt A1 example encrypted jwt" in {
    // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.1
    val jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iN" +
      "qhWXaKH4MqAkQtMoNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLGTkND09XyjORj_CHAgOPJ-Sd8ONQRnJ" +
      "vWn_hXV1BNMHzUjPyYwEsRhDhzjAD26imasOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52YCitxoQVPzj" +
      "bl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a1rZgN5TiysnmzTROF869lQ.AxY8DCtDaGlsbGljb3RoZQ.MKOle7UQrG" +
      "6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaMHDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8.fiK51VwhsxJ" +
      "-siBMR-YFiA"
    val expectedPayload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    val run =
      for
        key <- EitherT(appendixA2.toPrivateKey[IO]())
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt,
          JoseConfiguration(skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF
        )(DecryptionPrimitive.decryptionKey[IO](key)))
        _ <- jwtClaims.expectedIssuers("joe").eLiftET[IO]
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1300819300L)).eLiftET[IO]
        expected <- decode[Id, JsonWebTokenClaims](expectedPayload).eLiftET[IO]
      yield
        jwtClaims.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false) &&
          expected == jwtClaims && nested.length == 1
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with jwt A2 example nested JWT" in {
    // an Example Nested JWT from https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.2
    val jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpy" +
      "k_XdcSmxvcM5_P296JXXtoHISr_DD_MqewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYEb9ERe-epKYE3xb" +
      "2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvhDuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVL" +
      "EHx6DYyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsqJGTO_z3Wfo5zsqwkxruxwA.UmVkbW9uZCBXQSA5O" +
      "DA1Mg.VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTBBLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-" +
      "pSL8GQSXnaamh9kX1mdh3M_TT-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10l56pPfAtrjEYw-7ygeMk" +
      "wBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZYKw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvrZ" +
      "XUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb28Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_n" +
      "NJgNliWtWpJ_ebuOpEl8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11UzBuo2WlgZ6hYi9-e3w29bR0C2-p" +
      "p3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ.AVO9iT5AV4CzvDJCdhSFlQ"
    val run =
      for
        decryptionKey <- EitherT(appendixA2.toPrivateKey[IO]())
        verificationKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        rsaPublicKey <- EitherT(appendixA1.toPublicKey[IO]())
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt,
          JoseConfiguration(skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF
        )(DecryptionPrimitive.decryptionKey[IO](decryptionKey)))
        (jwtClaims2, nested2) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireEncryption = true))(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.decryptionKey(decryptionKey)))
        _ <- jwtClaims2.requireExpirationTime.eLiftET[IO]
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1300819300L), 30.seconds).eLiftET[IO]
        _ <- jwtClaims2.expectedIssuers("joe").eLiftET[IO]
        // then some negative tests w/ null or wrong keys
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireEncryption = true))(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireEncryption = true))(
          VerificationPrimitive.verificationKey[IO](None)
        )(DecryptionPrimitive.decryptionKey(decryptionKey)).map(_.swap.asError))
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireEncryption = true))(
          VerificationPrimitive.verificationKey[IO](Some(rsaPublicKey))
        )(DecryptionPrimitive.decryptionKey(decryptionKey)).map(_.swap.asError))
      yield
        List(nested1, nested2).forall(nested => nested.length == 2 && nested.head.isInstanceOf[JsonWebSignature] &&
          nested.tail.head.isInstanceOf[JsonWebEncryption]) &&
          List(jwtClaims1, jwtClaims2).forall(jwtClaims => jwtClaims.issuer.contains("joe") &&
            jwtClaims.expirationTime.contains(Instant.ofEpochSecond(1300819380L)) &&
            jwtClaims.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with jwt sec 31 example JWT" in {
    // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3.1
    val jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9l" +
      "eGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjA" +
      "zZr1Z9CAow\"}"
    val run =
      for
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF))
        jsonWebKey <- decode[Id, JsonWebKey](jwk).eLiftET[IO]
        jwks = JsonWebKeySet(jsonWebKey)
        (jwtClaims2, nested2) <- EitherT(JsonWebToken.getClaims[IO](jwt)(jwks.verificationPrimitives)(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1300819372L)).eLiftET[IO]
        _ <- jwtClaims2.expectedIssuers("joe").eLiftET[IO]
        _ <- jwtClaims2.requireExpirationTime.eLiftET[IO]
        verificationKey <- EitherT(jsonWebKey.toKey[IO]())
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(requireEncryption = true))(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
      yield
        jwtClaims1.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false) && nested1.length == 1 &&
          jwtClaims2.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false) && nested2.length == 1
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with skip signature verification" in {
    val jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9l" +
      "eGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val run =
      for
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(
          skipSignatureVerification = true))(
          VerificationPrimitive.defaultVerificationPrimitivesF
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1300819372L)).eLiftET[IO]
        _ <- jwtClaims.expectedIssuers("joe").eLiftET[IO]
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      yield
        jwtClaims.ext("http://example.com/is_root").flatMap(_.asBoolean).getOrElse(false) && nested.length == 1
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "failed with jwt bad sig" in {
    val jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTkwMDgxOTM4MCwKICJodHRwOi8vZXhh" +
      "bXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjA" +
      "zZr1Z9CAow\"}"
    val run =
      for
        jsonWebKey <- decode[Id, JsonWebKey](jwk).eLiftET[IO]
        verificationKey <- EitherT(jsonWebKey.toKey[IO]())
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1900000380L)).eLiftET[IO]
        _ <- jwtClaims.expectedIssuers("joe").eLiftET[IO]
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      yield
        ()
    run.value.asserting(value => assert(value.isLeft))
  }

  "JsonWebToken getClaims" should "succeed with algorithm constraints" in {
    val jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.DDyrirrztC88OaDtT" +
      "kkNgNIyZqQd4gjWrab9KkiBnyOULjWZWt-IAg.Obun_t7l3FYqNUqyW46syg.ChlzoLTN1ovJP9PLHlirc-_yvP4ya_5gdhDSKiZnifS9MjCb" +
      "eMYebkOCxSHexs09PBbPv30JwtIyM7caqkSNggA8HT_ub1moMpx0uOFhTE9dpdY4Wb4Ym6mqtIQhdwLymDVCI6vRn-NH88vdLluGSYYLhelgc" +
      "L05qeWJQKzV3mxopgM-Q7N7LycXrodqTdvM.ay9pwehz96tJgRKvSwASDg"
    val run =
      for
        wrapKey <- decode[Id, JsonWebKey]("{\"kty\":\"oct\",\"k\":\"sUMs42PKNsKn9jeGJ2szKA\"}").eLiftET[IO]
        decryptionKey <- EitherT(wrapKey.toKey[IO]())
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF
        )(DecryptionPrimitive.decryptionKey(decryptionKey)))
        macKey <- decode[Id, JsonWebKey]("{\"kty\":\"oct\",\"k\":\"j-QRollN4PYjebWYcTl32YOGWfdpXi_YYHu03Ifp8K4\"}")
          .eLiftET[IO]
        verificationKey <- EitherT(macKey.toKey[IO]())
        (jwtClaims2, nested2) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.decryptionKey(decryptionKey)))
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1419982016L)).eLiftET[IO]
        _ <- jwtClaims2.expectedAudiences("canada").eLiftET[IO]
        _ <- jwtClaims2.expectedIssuers("usa").eLiftET[IO]
        _ <- jwtClaims2.requireExpirationTime.eLiftET[IO]
        wrongMacJsonWebKey <- decode[Id, JsonWebKey]("{\"kty\":\"oct\",\"k\":\"___RollN4PYjebWYcTl32YOGWfdpXi_YYHu03" +
          "Ifp8K4\"}").eLiftET[IO]
      yield
        jwtClaims1.ext("message").flatMap(_.asString).contains("eh") &&
          jwtClaims2.ext("message").flatMap(_.asString).contains("eh")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with custom validator test" in {
    // {"iss":"same","aud":"same","exp":1420046060}
    val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiYXVkIjoic2FtZSIsImV4cCI6MTQyMDA0NjA2MH0.O1w_nkfQMZvEEvJ0Pach" +
      "0gPmJUMW8o4aFlA1f2c8m-I"
    val run =
      for
        jsonWebKey <- decode[Id, JsonWebKey]("{\"kty\":\"oct\",\"k\":\"IWlxz1h43wKzyigIXNn-dTRBu89M9L8wmJK4zZmUXrQ\"}")
          .eLiftET[IO]
        verificationKey <- EitherT(jsonWebKey.toKey[IO]())
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1420046040L)).eLiftET[IO]
        _ <- jwtClaims.expectedAudiences("same", "different").eLiftET[IO]
        _ <- jwtClaims.expectedIssuers("same").eLiftET[IO]
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      yield
        nested.length == 1 && jwtClaims.audience.flatMap(_.headOption).exists(jwtClaims.issuer.contains)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with custom error code validator test" in {
    // {"iss":"same","aud":"same","exp":1420046060}
    val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiYXVkIjoic2FtZSIsImV4cCI6MTQyMDA0NjA2MH0.O1w_nkfQMZvEEvJ0Pach" +
      "0gPmJUMW8o4aFlA1f2c8m-I"
    val run =
      for
        jsonWebKey <- decode[Id, JsonWebKey]("{\"kty\":\"oct\",\"k\":\"IWlxz1h43wKzyigIXNn-dTRBu89M9L8wmJK4zZmUXrQ\"}")
          .eLiftET[IO]
        verificationKey <- EitherT(jsonWebKey.toKey[IO]())
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.verificationKey(Some(verificationKey))
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1420046040L)).eLiftET[IO]
        _ <- jwtClaims.expectedAudiences("same", "different").eLiftET[IO]
        _ <- jwtClaims.expectedIssuers("same").eLiftET[IO]
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      yield
        nested.length == 1 && jwtClaims.audience.flatMap(_.headOption).exists(jwtClaims.issuer.contains)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with error expired error code validation" in {
    val run =
      for
        now <- EitherT(Clock[IO].realTimeInstant.asError)
        jwtClaims = JsonWebTokenClaims(issuer = Some("ISS"), subject = Some("SUB"), audience = Some(Set("AUD")),
          expirationTime = Some(now.minus(1.minute)))
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        jws <- EitherT(JsonWebSignature.signJson[IO, JsonWebTokenClaims](JoseHeader(Some(RS256)), jwtClaims,
          Some(privateKey)))
        jwt <- jws.compact.eLiftET[IO]
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        (claims, _) <- EitherT(JsonWebToken.getClaims[IO](jwt)(VerificationPrimitive.verificationKey(Some(publicKey)))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- claims.checkTime(now).swap.asError.eLiftET[IO]
      yield
        true
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken getClaims" should "succeed with missing cty in nested" in {
    // Nested jwt without "cty":"JWT" -> expect failure here as the cty is a MUST for nesting
    // setEnableLiberalContentTypeHandling() on the builder will enable a best effort to deal with the content even
    // when cty isn't specified
    val jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsIngiOiIwR" +
      "Gk0VTBZQ0R2NHAtS2hETUZwUThvY0FsZzA2SEwzSHR6UldRbzlDLWV3IiwieSI6IjBfVFJjR1Y3Qy05d0xseFJZSExJOFlKTXlET2hWNW5YeH" +
      "VPMGdRVmVxd0EiLCJjcnYiOiJQLTI1NiJ9fQ..xw5H8Kztd_sqzbXjt4GKUg.YNa163HLj7MwlvjzGihbOHnJ2PC3NOTnnvVOanuk1O9XFJ97" +
      "pbbHHQzEeEwG6jfvDgdmlrLjcIJkSu1U8qRby7Xr4gzP6CkaDPbKwvLveETZSNdmZh37XKfnQ4LvKgiko6OQzyLYG1gc97kUOeikXTYVaYaeV" +
      "1838Bi4q3DsIG-j4ZESg0-ePQesw56A80AEE3j6wXwZ4vqugPP9_ogZzkPFcHf1lt3-A4amNMjDbV8.u-JJCoakXI55BG2rz_kBlg"
    val run =
      for
        sigJwk <- decode[Id, AsymmetricJsonWebKey]("{\"kty\":\"EC\",\"x\":\"loF6m9WAW_GKrhoh48ctg_d78fbIsmUb02XDOwJj" +
          "59c\",\"y\":\"kDCHDkCbWjeX8DjD9feQKcndJyerdsLJ4VZ5YSTWCoU\",\"crv\":\"P-256\",\"d\":\"6D1C9gJsT9KXNtTNyqg" +
          "pdyQuIrK-qzo0_QJOVe9DqJg\"}").eLiftET[IO]
        encJwk <- decode[Id, AsymmetricJsonWebKey]("{\"kty\":\"EC\",\"x\":\"PNbMydlpYRBFTYn_XDFvvRAFqE4e0EJmK6-zULTV" +
          "ERs\",\"y\":\"dyO9wGVgKS3gtP5bx0PE8__MOV_HLSpiwK-mP1RGZgk\",\"crv\":\"P-256\",\"d\":\"FIs8wVojHBdl7vkiZVn" +
          "LBPw5S9lbn4JF2WWY1OTupic\"}").eLiftET[IO]
        sigKey <- EitherT(sigJwk.toPublicKey[IO]())
        encKey <- EitherT(encJwk.toPrivateKey[IO]())
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfiguration(
          skipSignatureVerification = true, liberalContentTypeHandling = true, requireSignature = false))(
          VerificationPrimitive.verificationKey(Some(sigKey))
        )(DecryptionPrimitive.decryptionKey(encKey)))
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.verificationKey(Some(sigKey))
        )(DecryptionPrimitive.decryptionKey(encKey)).map(_.swap.asError))
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1420219088L)).eLiftET[IO]
        _ <- jwtClaims.expectedAudiences("canada").eLiftET[IO]
        _ <- jwtClaims.expectedIssuers("usa").eLiftET[IO]
        _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      yield
        jwtClaims.ext("message").flatMap(_.asString).contains("eh") && nested.length == 2 &&
          nested.head.isInstanceOf[JsonWebSignature] && nested.tail.head.isInstanceOf[JsonWebEncryption]
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebTokenGetClaimsFlatSpec
