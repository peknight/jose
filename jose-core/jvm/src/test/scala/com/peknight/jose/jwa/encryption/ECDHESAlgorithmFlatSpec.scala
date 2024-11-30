package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import com.peknight.security.cipher.AES
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class ECDHESAlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "ECDH-ES" should "succeed with example jwa appendix C" in {
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_" +
      "PxMQ\",\n \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFAS" +
      "Rl6BfUqdw\"\n}"
    val ephemeralJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHK" +
      "W5SV0\",\n \"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\n \"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCu" +
      "md-MToTmIo\"\n}"
    val agreementPartyUInfo = "QWxpY2U"
    val agreementPartyVInfo = "Qm9i"
    val encodedContentEncryptionKey = "VqqN6vgjbSBcIijNcacQGg"
    val run =
      for
        receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
        receiverPublicKey <- EitherT(receiverJwk.toPublicKey[IO]())
        receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
        ephemeralJwk <- decode[Id, EllipticCurveJsonWebKey](ephemeralJwkJson).eLiftET[IO]
        ephemeralPublicKey <- EitherT(ephemeralJwk.toPublicKey[IO]())
        ephemeralPrivateKey <- EitherT(ephemeralJwk.toPrivateKey[IO]())
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
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUP" +
      "oYgk\",\n \"y\":\"g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU\",\n \"d\":\"KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCc" +
      "ZQ-19rYs4\"\n}"
    val ephemeralJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"UWlKW_GHsZa1ikOUPocsMi2pNh_1K2vhn6ZjJq" +
      "ALOK8\",\n \"y\":\"n2oj0Z6EYgzRDmeROILD4fp2zAMGLQzmI8G1k5nsev0\"\n}"
    val encodedContentEncryptionKey = "bqXVMd1yd5E08Wy2T1U9m9Q5DEjj7-BYIyWUgazzZkA"
    val run =
      for
        receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
        receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
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
    val jwkJson = "{\"kty\":\"EC\",\"x\":\"fXx-DfOsmecjKh3VrLZFsF98Z1nutsL4UdFTdgA8S7Y\",\"y\":\"LGzyJY99aqKk52UIExc" +
      "NFSTs0S7HnNzQ-DRWBTHDad4\",\"crv\":\"P-256\",\"d\":\"OeVCWbXuFuJ9U16q7bhLNoKPLLnK-yTx95grzfvQ2l4\"}"
    val cs = "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJ3ZlRHNVFHZkItNHUxan" +
      "VUUEN1aTNESXhFTV82ZUs5ZEk5TXNZckpxWDRnIiwieSI6Ik8yanlRbHQ2TXFGTGtqMWFCWW1aNXZJWHFVRHh6Ulk3dER0WmdZUUVNa0kiLCJ" +
      "jcnYiOiJQLTI1NiJ9fQ..mk4wQzGSSeZ8uSgEYTIetA.fCw3-TosL4p0D5fEXw0bEA.9mPsdmGTVoVexXqEOdN5VUKk-ZNtfOtUfbdjVHoko_o"
    val text = "It works!"
    testECDHAndAESCBCHmacSHA2(jwkJson, cs, text)
  }

  "ECDH-ES" should "succeed with decrypt precomputed P-384 ECDH and A192CBC-HS384" in {
    val jwkJson = "{\"kty\":\"EC\",\"x\":\"nBr92fh2JsEjIF1LR5PKICBeHNIBe0xb7nlBrrU3WoWgfJYfXve1jxC-5VT5EPLt\",\"y\":" +
      "\"sUAxL3L5lJdzFUSR9EHLniuBhEbvXfPa_3OiR6Du0_GOlFXXIi4UmbNpk10_Thfq\",\"crv\":\"P-384\",\"d\":\"0f0NnWg__Qgqjj" +
      "3fl2gAlsID4Ni41FR88cmZPVgb6ch-ZShuVJRjoxymCuzVP7Gi\"}"
    val cs = "eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJsX3hXdzIyb1NfOWZGbV" +
      "96amNzYkstd3R3d0RHSlRQLUxnNFVBWDI3WWF1b1YwNml2emwtcm1ra2h6ci11SDBmIiwieSI6IloyYmVnbzBqeE9nY0YtNVp4SFNBOU5jZDV" +
      "COW8wUE1pSVlRbm9sWkNQTHA3YndPd1RLUEZaaFZVUlFPSjdoeUciLCJjcnYiOiJQLTM4NCJ9fQ..jSWP7pfa4KcpqKWZ1x8awg.osb-5641E" +
      "j1Uon_f3U8bNw.KUQWwb35Gxq3YQ34_AVkebugx4rxq1lO\n"
    val text = "Please work..."
    testECDHAndAESCBCHmacSHA2(jwkJson, cs, text)
  }

  "ECDH-ES" should "succeed with decrypt precomputed P-521 ECDH and A256CBC-HS512" in {
    val jwkJson = "{\"kty\":\"EC\",\"x\":\"AH3rqSYjKue50ThW0qq_qQ76cNtqWrc7hU6kZR6akxy8iTf8ugcpqnbgbi98AgSwIqgJZDBMC" +
      "k-8eoiGaf3R_kDD\",\"y\":\"AeafPdJjHLf6pK5V7iyMsL3-6MShpHS6jXQ8m-Bcbp06yxAMn6TJbdkacvj45dy_pdh1s6XZwoxRxNETg_g" +
      "j-hq9\",\"crv\":\"P-521\",\"d\":\"AB2tm9vgGe2BaxZmJQ016GY-U7NV_EWhrPsLDC5l9tAM9DGEwI2cT2HcO20Z6CQndw0ZhqLZ6ME" +
      "vS8siL-SCxIl2\"}\n"
    val cs = "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJBQ1RLMlVPSjJ6SVk3U1" +
      "U4T0xkaG1QQmE4ZUVpd2JrX09UMXE0MHBsRlRwQmJKUXg3YWdqWG9LYml2NS1OTXB6eXZySm1rblM3SjNRUWlUeFgwWmtjemhEIiwieSI6IkF" +
      "XeTZCR1dkZld2ekVNeGIxQklCQnZmRDJ4bEh6Rjk2YzVVRVQ4SFBUS0RSeUJyMnQ4T2dTX1J2MnNoUmxGbXlqUWpyX25uQk94akcxVTZNWDNl" +
      "Z2VETzciLCJjcnYiOiJQLTUyMSJ9fQ..EWqSGntxbO_Y_6JRjFkCgg.DGjDNjAYdsnYTpUFJi1gEI4YtNd7gBPMjD3CDH047RAwZKTme6Ah_z" +
      "tzxSfVg5kG.yGm5jn2LtbFXaK_yf0b0932sI2O77j2gwmL1Y09YC_Y"
    val text = "And also the working here would be nice."
    testECDHAndAESCBCHmacSHA2(jwkJson, cs, text)
  }

  def testECDHAndAESCBCHmacSHA2(jwkJson: String, jweCompact: String, text: String): IO[Assertion] =
    val run =
      for
        jwk <- decode[Id, EllipticCurveJsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toPrivateKey[IO]())
        jwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
        res <- EitherT(jwe.decryptUtf8[IO](key))
      yield
        res == text
    run.value.asserting(value => assert(value.getOrElse(false)))

end ECDHESAlgorithmFlatSpec
