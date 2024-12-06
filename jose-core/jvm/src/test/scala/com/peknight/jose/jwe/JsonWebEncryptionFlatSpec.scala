package com.peknight.jose.jwe

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.encryption.*
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.jose.jwk.{JsonWebKey, appendixA1, appendixA2}
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebEncryptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  "JsonWebEncryption" should "succeed with jwe example A3" in {
    val jweCsFromAppendixA3Compact = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwb" +
      "oJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJv" +
      "ceFICbCVQ"
    val jwkJson = "\n{\"kty\":\"oct\",\n \"k\":\"GawgguFyGrWKav7AX4VKUg\"\n}"
    val plaintext = "Live long and prosper."
    val run =
      for
        jwk <- decode[Id, OctetSequenceJsonWebKey](jwkJson).eLiftET[IO]
        key <- jwk.toKey.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCsFromAppendixA3Compact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](key))
      yield
        decrypted == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with jwe example A2" in {
    val jweCsFromAppendixA2Compact = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLO" +
      "mwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoO" +
      "egEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh" +
      "cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaG" +
      "lsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw"
    val plaintext = "Live long and prosper."
    val run =
      for
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        jwe <- JsonWebEncryption.parse(jweCsFromAppendixA2Compact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](privateKey))
      yield
        decrypted == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with jwe example A1" in {
    val csCompact = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJ" +
      "RgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S" +
      "4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamav" +
      "o35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0l" +
      "tJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
    val plaintext = "The true sign of intelligence is not knowledge but imagination."
    val run =
      for
        privateKey <- EitherT(appendixA1.toPrivateKey[IO]())
        jwe <- JsonWebEncryption.parse(csCompact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](privateKey))
      yield
        decrypted == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with happy round trip RSA1_5 and A128CBC-HS256" in {
    val plaintext = "Some text that's on double secret probation"
    val run =
      for
        publicKey <- EitherT(appendixA2.toPublicKey[IO]())
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        jwe <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(RSA1_5), Some(`A128CBC-HS256`)), plaintext,
          publicKey))
        compact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(compact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](privateKey))
      yield
        decrypted == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with happy round trip RSA-OAEP and A128CBC-HS256" in {
    val plaintext = "Some text that's on double secret probation"
    val run =
      for
        publicKey <- EitherT(appendixA2.toPublicKey[IO]())
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        jwe <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(`RSA-OAEP`), Some(`A128CBC-HS256`)),
          plaintext, publicKey))
        compact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(compact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](privateKey))
      yield
        decrypted == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with happy round trip Direct and A128CBC-HS256" in {
    val plaintext = "Some sensitive info"
    val run =
      for
        key <- EitherT(`A128CBC-HS256`.cekAlgorithm.keySizeGenerateKey[IO](`A128CBC-HS256`.cekByteLength * 8).asError)
        jwe <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(dir), Some(`A128CBC-HS256`)), plaintext, key))
        compact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(compact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](key))
      yield
        decrypted == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "failed with accepting compact serialization with malformed JWE" in {
    // modified to have only 4 parts, which isn't legal, from http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#appendix-A.3.11
    val damagedVersionOfJweCsFromAppendixA3 = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLv" +
      "tgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
    assert(JsonWebEncryption.parse(damagedVersionOfJweCsFromAppendixA3).isLeft)
  }
end JsonWebEncryptionFlatSpec
