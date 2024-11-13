package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwx.toBytes
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class AESCBCHmacSHA2AlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

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
        plaintextBytes <- toBytes(plaintext).eLiftET[IO]
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
        plaintextBytes <- toBytes(text).eLiftET[IO]
        rawCek <- EitherT(randomBytes[IO](`A128CBC-HS256`.cekByteLength).asError)
        contentEncryptionParts <- EitherT(`A128CBC-HS256`.encrypt[IO](rawCek, plaintextBytes, aad, None).asError)
        decrypted <- EitherT(`A128CBC-HS256`.decrypt[IO](rawCek, contentEncryptionParts.initializationVector,
          contentEncryptionParts.ciphertext, contentEncryptionParts.authenticationTag, aad))
        decryptedText <- decrypted.decodeUtf8.asError.eLiftET
      yield
        decryptedText == text
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

end AESCBCHmacSHA2AlgorithmFlatSpec
