package com.peknight.jose.jwe

import cats.Id
import cats.data.EitherT
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.effect.{IO, Sync}
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.{MissingKey, MissingPrivateKey}
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwa.encryption.*
import com.peknight.jose.jwk.JsonWebKey.{EllipticCurveJsonWebKey, OctetSequenceJsonWebKey}
import com.peknight.jose.jwk.{JsonWebKey, appendixA1, appendixA2}
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.AES
import com.peknight.security.error.PointNotOnCurve
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class JsonWebEncryptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private val rawCek = ByteVector(4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
    212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207)
  private val plaintext = "Live long and prosper."
  private val encodedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
  private val encodedCiphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
  private val encodedAuthenticationTag = "9hH0vgRfYgPnAHOd8stkvw"

  "A128CBC-HS256" should "succeed with example encrypt from jwe appendix 2" in {
    val iv = ByteVector(3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101)
    val run =
      for
        plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        contentEncryptionParts <- EitherT(`A128CBC-HS256`.encrypt[IO](rawCek, plaintextBytes, aad, Some(iv)).asError)
        ciphertext = Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext).value
        authenticationTag = Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag).value
      yield
        ciphertext == encodedCiphertext && authenticationTag == encodedAuthenticationTag
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A128CBC-HS256" should "succeed with example decrypt from jwe appendix 2" in {
    val encodedIv = "AxY8DCtDaGlsbGljb3RoZQ"
    val run =
      for
        ivBase <- Base64UrlNoPad.fromString(encodedIv).eLiftET[IO]
        iv <- EitherT(ivBase.decode[IO])
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        ciphertextBase <- Base64UrlNoPad.fromString(encodedCiphertext).eLiftET[IO]
        ciphertext <- EitherT(ciphertextBase.decode[IO])
        authenticationTagBase <- Base64UrlNoPad.fromString(encodedAuthenticationTag).eLiftET[IO]
        authenticationTag <- EitherT(authenticationTagBase.decode[IO])
        decrypted <- EitherT(`A128CBC-HS256`.decrypt[IO](rawCek, iv, ciphertext, authenticationTag, aad))
        decryptedText <- decrypted.decodeUtf8.asError.eLiftET
      yield
        decryptedText == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A128CBC-HS256" should "succeed with round trip" in {
    val text = "I'm writing this test on a flight to Zurich"
    val run =
      for
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        plaintextBytes <- ByteVector.encodeUtf8(text).asError.eLiftET[IO]
        rawCek <- EitherT(randomBytes[IO](`A128CBC-HS256`.cekByteLength).asError)
        contentEncryptionParts <- EitherT(`A128CBC-HS256`.encrypt[IO](rawCek, plaintextBytes, aad, None).asError)
        decrypted <- EitherT(`A128CBC-HS256`.decrypt[IO](rawCek, contentEncryptionParts.initializationVector,
          contentEncryptionParts.ciphertext, contentEncryptionParts.authenticationTag, aad))
        decryptedText <- decrypted.decodeUtf8.asError.eLiftET
      yield
        decryptedText == text
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A128KW" should "succeed with A128CBC-HS256" in {
    val jwkJson = "\n     {\"kty\":\"oct\",\n      \"k\":\"GawgguFyGrWKav7AX4VKUg\"\n     }"
    val encodedEncryptedKey = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    val run =
      for
        jwk <- decode[Id, OctetSequenceJsonWebKey](jwkJson).eLiftET[IO]
        managementKey <- jwk.toKey.eLiftET[IO]
        contentEncryptionKeys <- EitherT(A128KW.encryptKey[IO](managementKey, `A128CBC-HS256`.cekByteLength,
          `A128CBC-HS256`.cekAlgorithm, Some(rawCek)))
        encryptedKey = Base64UrlNoPad.fromByteVector(contentEncryptionKeys.encryptedKey).value
        key <- EitherT(A128KW.decryptKey[IO](managementKey, contentEncryptionKeys.encryptedKey,
          `A128CBC-HS256`.cekByteLength, `A128CBC-HS256`.cekAlgorithm))
      yield
        encryptedKey == encodedEncryptedKey && ByteVector(key.getEncoded) === rawCek
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A256GCM" should "succeed" in {
    val plaintext = "The true sign of intelligence is not knowledge but imagination."
    val encodedHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
    val encodedCiphertext = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"
    val encodedAuthenticationTag = "XFBoMYUZodetZdvTiFvSkQ"
    val rawCek = ByteVector(177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91,
      112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252)
    val iv = ByteVector(227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219)
    val run =
      for
        plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        contentEncryptionParts <- EitherT(A256GCM.encrypt[IO](rawCek, plaintextBytes, aad, Some(iv)).asError)
        ciphertext = Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext).value
        authenticationTag = Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag).value
        decrypted <- EitherT(A256GCM.decrypt[IO](rawCek, contentEncryptionParts.initializationVector,
          contentEncryptionParts.ciphertext, contentEncryptionParts.authenticationTag, aad))
      yield
        ciphertext == encodedCiphertext && authenticationTag == encodedAuthenticationTag && decrypted === plaintextBytes

    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "ECDH-ES" should "succeed with example jwa appendix C" in {
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\n \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\n}"
    val ephemeralJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\",\n \"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\n \"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"\n}"
    val agreementPartyUInfo = "QWxpY2U"
    val agreementPartyVInfo = "Qm9i"
    val encodedContentEncryptionKey = "VqqN6vgjbSBcIijNcacQGg"
    val run =
      for
        receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
        receiverPublicKey <- EitherT(receiverJwk.toPublicKey[IO]())
        receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
        receiverPrivateKey <- receiverPrivateKey.toRight(MissingPrivateKey.label("receiverPrivateKey")).eLiftET[IO]
        ephemeralJwk <- decode[Id, EllipticCurveJsonWebKey](ephemeralJwkJson).eLiftET[IO]
        ephemeralPublicKey <- EitherT(ephemeralJwk.toPublicKey[IO]())
        ephemeralPrivateKey <- EitherT(ephemeralJwk.toPrivateKey[IO]())
        ephemeralPrivateKey <- ephemeralPrivateKey.toRight(MissingPrivateKey.label("ephemeralPrivateKey")).eLiftET[IO]
        apuBase <- Base64UrlNoPad.fromString(agreementPartyUInfo).eLiftET[IO]
        apvBase <- Base64UrlNoPad.fromString(agreementPartyVInfo).eLiftET[IO]
        apu <- apuBase.decode[Id].eLiftET[IO]
        apv <- apvBase.decode[Id].eLiftET[IO]
        contentEncryptionKeys <- EitherT(`ECDH-ES`.handleEncryptKey[IO](receiverPublicKey, A128GCM.blockSize,
          ephemeralPublicKey, ephemeralPrivateKey, Some(A128GCM), Some(apu), Some(apv)))
        contentEncryptionKey = Base64UrlNoPad.fromByteVector(contentEncryptionKeys.contentEncryptionKey).value
        derivedKey <- EitherT(`ECDH-ES`.decryptKey[IO](receiverPrivateKey, contentEncryptionKeys.encryptedKey,
          A128GCM.blockSize, AES, None, Some(A128GCM), Some(ephemeralPublicKey), Some(apu), Some(apv)))
        key = Base64UrlNoPad.fromByteVector(ByteVector(derivedKey.getEncoded)).value
      yield
        contentEncryptionKeys.encryptedKey.isEmpty && contentEncryptionKey == encodedContentEncryptionKey &&
          key == encodedContentEncryptionKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "ECDH-ES" should "succeed with dv256" in {
    /*
     * A working test w/ data produced by Dmitry Vsekhvalnov doing ECDH with P-256 + ConcatKDF to produce a 256 bit key
     * ---
     * Ok, data below. Everything base64url encoded. partyUInfo=partyVInfo=[0,0,0,0] in all samples.
     *
     * Curve P-256, 256 bit key (match to jose4j and to spec sample, provided as reference)
     *
     * X = BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk
     * Y = g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU
     * D = KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4
     *
     * ephemeral X = UWlKW_GHsZa1ikOUPocsMi2pNh_1K2vhn6ZjJqALOK8
     * ephemeral Y = n2oj0Z6EYgzRDmeROILD4fp2zAMGLQzmI8G1k5nsev0
     *
     * algId = AAAADUExMjhDQkMtSFMyNTY
     * suppPubInfo = AAABAA
     *
     * derived key = bqXVMd1yd5E08Wy2T1U9m9Q5DEjj7-BYIyWUgazzZkA
     */
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk\",\n \"y\":\"g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU\",\n \"d\":\"KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4\"\n}"
    val ephemeralJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"UWlKW_GHsZa1ikOUPocsMi2pNh_1K2vhn6ZjJqALOK8\",\n \"y\":\"n2oj0Z6EYgzRDmeROILD4fp2zAMGLQzmI8G1k5nsev0\"\n}"
    val encodedContentEncryptionKey = "bqXVMd1yd5E08Wy2T1U9m9Q5DEjj7-BYIyWUgazzZkA"
    val run =
      for
        receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
        receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
        receiverPrivateKey <- receiverPrivateKey.toRight(MissingPrivateKey.label("receiverPrivateKey")).eLiftET[IO]
        ephemeralJwk <- decode[Id, EllipticCurveJsonWebKey](ephemeralJwkJson).eLiftET[IO]
        ephemeralPublicKey <- EitherT(ephemeralJwk.toPublicKey[IO]())
        derivedKey <- EitherT(`ECDH-ES`.decryptKey[IO](receiverPrivateKey, ByteVector.empty, 32, AES, None,
          Some(`A128CBC-HS256`), Some(ephemeralPublicKey)))
        key = Base64UrlNoPad.fromByteVector(ByteVector(derivedKey.getEncoded)).value
      yield
        key == encodedContentEncryptionKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "ECDH-ES" should "succeed with decrypt precomputed P-256 ECDH and A256CBC-HS512" in {
    val jwkJson = "{\"kty\":\"EC\",\"x\":\"fXx-DfOsmecjKh3VrLZFsF98Z1nutsL4UdFTdgA8S7Y\",\"y\":\"LGzyJY99aqKk52UIExcNFSTs0S7HnNzQ-DRWBTHDad4\",\"crv\":\"P-256\",\"d\":\"OeVCWbXuFuJ9U16q7bhLNoKPLLnK-yTx95grzfvQ2l4\"}"
    val cs = "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJ3ZlRHNVFHZkItNHUxanVUUEN1aTNESXhFTV82ZUs5ZEk5TXNZckpxWDRnIiwieSI6Ik8yanlRbHQ2TXFGTGtqMWFCWW1aNXZJWHFVRHh6Ulk3dER0WmdZUUVNa0kiLCJjcnYiOiJQLTI1NiJ9fQ..mk4wQzGSSeZ8uSgEYTIetA.fCw3-TosL4p0D5fEXw0bEA.9mPsdmGTVoVexXqEOdN5VUKk-ZNtfOtUfbdjVHoko_o"
    val text = "It works!"
    testECDHAndAESCBCHmacSHA2(jwkJson, cs, text)
  }

  "ECDH-ES" should "succeed with decrypt precomputed P-384 ECDH and A192CBC-HS384" in {
    val jwkJson = "{\"kty\":\"EC\",\"x\":\"nBr92fh2JsEjIF1LR5PKICBeHNIBe0xb7nlBrrU3WoWgfJYfXve1jxC-5VT5EPLt\",\"y\":\"sUAxL3L5lJdzFUSR9EHLniuBhEbvXfPa_3OiR6Du0_GOlFXXIi4UmbNpk10_Thfq\",\"crv\":\"P-384\",\"d\":\"0f0NnWg__Qgqjj3fl2gAlsID4Ni41FR88cmZPVgb6ch-ZShuVJRjoxymCuzVP7Gi\"}"
    val cs = "eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJsX3hXdzIyb1NfOWZGbV96amNzYkstd3R3d0RHSlRQLUxnNFVBWDI3WWF1b1YwNml2emwtcm1ra2h6ci11SDBmIiwieSI6IloyYmVnbzBqeE9nY0YtNVp4SFNBOU5jZDVCOW8wUE1pSVlRbm9sWkNQTHA3YndPd1RLUEZaaFZVUlFPSjdoeUciLCJjcnYiOiJQLTM4NCJ9fQ..jSWP7pfa4KcpqKWZ1x8awg.osb-5641Ej1Uon_f3U8bNw.KUQWwb35Gxq3YQ34_AVkebugx4rxq1lO\n"
    val text = "Please work..."
    testECDHAndAESCBCHmacSHA2(jwkJson, cs, text)
  }

  "ECDH-ES" should "succeed with decrypt precomputed P-521 ECDH and A256CBC-HS512" in {
    val jwkJson = "{\"kty\":\"EC\",\"x\":\"AH3rqSYjKue50ThW0qq_qQ76cNtqWrc7hU6kZR6akxy8iTf8ugcpqnbgbi98AgSwIqgJZDBMCk-8eoiGaf3R_kDD\",\"y\":\"AeafPdJjHLf6pK5V7iyMsL3-6MShpHS6jXQ8m-Bcbp06yxAMn6TJbdkacvj45dy_pdh1s6XZwoxRxNETg_gj-hq9\",\"crv\":\"P-521\",\"d\":\"AB2tm9vgGe2BaxZmJQ016GY-U7NV_EWhrPsLDC5l9tAM9DGEwI2cT2HcO20Z6CQndw0ZhqLZ6MEvS8siL-SCxIl2\"}\n"
    val cs = "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJBQ1RLMlVPSjJ6SVk3U1U4T0xkaG1QQmE4ZUVpd2JrX09UMXE0MHBsRlRwQmJKUXg3YWdqWG9LYml2NS1OTXB6eXZySm1rblM3SjNRUWlUeFgwWmtjemhEIiwieSI6IkFXeTZCR1dkZld2ekVNeGIxQklCQnZmRDJ4bEh6Rjk2YzVVRVQ4SFBUS0RSeUJyMnQ4T2dTX1J2MnNoUmxGbXlqUWpyX25uQk94akcxVTZNWDNlZ2VETzciLCJjcnYiOiJQLTUyMSJ9fQ..EWqSGntxbO_Y_6JRjFkCgg.DGjDNjAYdsnYTpUFJi1gEI4YtNd7gBPMjD3CDH047RAwZKTme6Ah_ztzxSfVg5kG.yGm5jn2LtbFXaK_yf0b0932sI2O77j2gwmL1Y09YC_Y"
    val text = "And also the working here would be nice."
    testECDHAndAESCBCHmacSHA2(jwkJson, cs, text)
  }

  def testECDHAndAESCBCHmacSHA2(jwkJson: String, jweCompact: String, text: String): IO[Assertion] =
    val run =
      for
        jwk <- decode[Id, EllipticCurveJsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toPrivateKey[IO]())
        key <- key.toRight(MissingKey.label("key")).eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](key))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == text
    run.value.asserting(value => assert(value.getOrElse(false)))

  "ECDH-ESWithAESWrap" should "succeed with round trip" in {
    val run =
      for
        algs <- filterAvailableAlgorithms[IO, `ECDH-ESWithAESWrapAlgorithm`](`ECDH-ESWithAESWrapAlgorithm`.values)
        encs <- filterAvailableAlgorithms[IO, AESCBCHmacSHA2Algorithm](AESCBCHmacSHA2Algorithm.values)
        tests =
          for
            alg <- algs
            enc <- encs
          yield jweRoundTrip(alg, enc)
        res <- tests.sequence.value.map(_.map(_.forall(identity)).getOrElse(false))
      yield
        res
    run.asserting(assert)
  }

  private def filterAvailableAlgorithms[F[_]: Sync, A <: AlgorithmIdentifier](algorithms: List[A]): F[List[A]] =
    algorithms.traverse[F, Option[A]](alg => alg.isAvailable[F].map(available => if available then alg.some else none))
      .map(_.collect {
        case Some(alg) => alg
      })

  private def jweRoundTrip(alg: `ECDH-ESWithAESWrapAlgorithm`, enc: AESCBCHmacSHA2Algorithm)
  : EitherT[IO, Error, Boolean] =
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\n \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\n}"
    val plaintext = "Gambling is illegal at Bushwood sir, and I never slice."
    for
      receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
      receiverPublicKey <- EitherT(receiverJwk.toPublicKey[IO]())
      receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
      receiverPrivateKey <- receiverPrivateKey.toRight(MissingPrivateKey.label("receiverPrivateKey")).eLiftET[IO]
      plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
      jwe <- EitherT(JsonWebEncryption.encrypt[IO](receiverPublicKey, plaintextBytes, JoseHeader(Some(alg), Some(enc))))
      jweCompact <- jwe.compact.eLiftET[IO]
      receiverJwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
      decrypted <- EitherT(receiverJwe.decrypt[IO](receiverPrivateKey))
      res <- decrypted.decodeUtf8.asError.eLiftET[IO]
    yield
      res == plaintext

  "ECDH-ES+A128KW" should "failed with invalid curve 1" in {
    val maliciousJweCompact = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w"
    pointNotOnCurve(maliciousJweCompact)
  }

  "ECDH-ES+A128KW" should "failed with invalid curve 2" in {
    val maliciousJweCompact = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A"
    pointNotOnCurve(maliciousJweCompact)
  }

  private def pointNotOnCurve(maliciousJweCompact: String): IO[Assertion] =
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\n \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\n}"
    val run =
      for
        receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
        receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
        receiverPrivateKey <- receiverPrivateKey.toRight(MissingPrivateKey.label("receiverPrivateKey")).eLiftET[IO]
        maliciousJwe <- JsonWebEncryption.parse(maliciousJweCompact).asError.eLiftET[IO]
        decrypted <- EitherT(maliciousJwe.decrypt[IO](receiverPrivateKey))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        true
    run.value.map {
      case Left(e: PointNotOnCurve) => true
      case _ => false
    }.asserting(assert)

  "JsonWebEncryption" should "succeed with jwe example A3" in {
    val jweCsFromAppendixA3Compact = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ"
    val jwkJson = "\n{\"kty\":\"oct\",\n \"k\":\"GawgguFyGrWKav7AX4VKUg\"\n}"
    val run =
      for
        jwk <- decode[Id, OctetSequenceJsonWebKey](jwkJson).eLiftET[IO]
        key <- jwk.toKey.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCsFromAppendixA3Compact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](key))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with jwe example A2" in {
    val jweCsFromAppendixA2Compact = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw"
    val run =
      for
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        privateKey <- privateKey.toRight(MissingPrivateKey.label("privateKey")).eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCsFromAppendixA2Compact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](privateKey))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with jwe example A1" in {
    val csCompact = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
    val plaintext = "The true sign of intelligence is not knowledge but imagination."
    val run =
      for
        privateKey <- EitherT(appendixA1.toPrivateKey[IO]())
        privateKey <- privateKey.toRight(MissingPrivateKey.label("privateKey")).eLiftET[IO]
        jwe <- JsonWebEncryption.parse(csCompact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](privateKey))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with happy round trip RSA1_5 and A128CBC-HS256" in {
    val plaintext = "Some text that's on double secret probation"
    val run =
      for
        publicKey <- EitherT(appendixA2.toPublicKey[IO]())
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        privateKey <- privateKey.toRight(MissingPrivateKey.label("privateKey")).eLiftET[IO]
        plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](publicKey, plaintextBytes, JoseHeader(Some(RSA1_5),
          Some(`A128CBC-HS256`))))
        compact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(compact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](privateKey))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with happy round trip RSA-OAEP and A128CBC-HS256" in {
    val plaintext = "Some text that's on double secret probation"
    val run =
      for
        publicKey <- EitherT(appendixA2.toPublicKey[IO]())
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        privateKey <- privateKey.toRight(MissingPrivateKey.label("privateKey")).eLiftET[IO]
        plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](publicKey, plaintextBytes, JoseHeader(Some(`RSA-OAEP`),
          Some(`A128CBC-HS256`))))
        compact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(compact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](privateKey))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "succeed with happy round trip Direct and A128CBC-HS256" in {
    val plaintext = "Some sensitive info"
    val run =
      for
        key <- EitherT(`A128CBC-HS256`.cekAlgorithm.keySizeGenerateKey[IO](`A128CBC-HS256`.cekByteLength * 8).asError)
        plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(dir),
          Some(`A128CBC-HS256`))))
        compact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(compact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](key))
        res <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        res == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebEncryption" should "failed with accepting compact serialization with malformed JWE" in {
    // modified to have only 4 parts, which isn't legal, from http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#appendix-A.3.11
    val damagedVersionOfJweCsFromAppendixA3 = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
    assert(JsonWebEncryption.parse(damagedVersionOfJweCsFromAppendixA3).isLeft)
  }
end JsonWebEncryptionFlatSpec
