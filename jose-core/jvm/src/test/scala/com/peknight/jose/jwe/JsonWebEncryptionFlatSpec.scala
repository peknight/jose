package com.peknight.jose.jwe

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.encryption.`A128CBC-HS256`
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class JsonWebEncryptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private val rawCek = ByteVector(4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
    212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207)
  private val iv = ByteVector(3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101)
  private val plainText = "Live long and prosper."
  private val encodedIv = "AxY8DCtDaGlsbGljb3RoZQ"
  private val encodedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
  private val encodedCiphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
  private val encodedAuthenticationTag = "9hH0vgRfYgPnAHOd8stkvw"

  "A128CBC-HS256" should "succeed with testExampleEncryptFromJweAppendix2" in {
    val run =
      for
        plainTextBytes <- ByteVector.encodeUtf8(plainText).asError.eLiftET[IO]
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET
        contentEncryptionParts <- EitherT(`A128CBC-HS256`.encrypt[IO](rawCek, plainTextBytes, aad, Some(iv)).asError)
      yield
        Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext).value == encodedCiphertext &&
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag).value == encodedAuthenticationTag
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A128CBC-HS256" should "succeed with testExampleDecryptFromJweAppendix2" in {
    val run =
      for
        ivBase <- Base64UrlNoPad.fromString(encodedIv).eLiftET[IO]
        iv <- EitherT(ivBase.decode[IO])
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET
        ciphertextBase <- Base64UrlNoPad.fromString(encodedCiphertext).eLiftET[IO]
        ciphertext <- EitherT(ciphertextBase.decode[IO])
        authenticationTagBase <- Base64UrlNoPad.fromString(encodedAuthenticationTag).eLiftET[IO]
        authenticationTag <- EitherT(authenticationTagBase.decode[IO])
        decrypted <- EitherT(`A128CBC-HS256`.decrypt[IO](rawCek, iv, ciphertext, authenticationTag, aad))
        decryptedText <- decrypted.decodeUtf8.asError.eLiftET
      yield
        decryptedText == plainText
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

end JsonWebEncryptionFlatSpec
