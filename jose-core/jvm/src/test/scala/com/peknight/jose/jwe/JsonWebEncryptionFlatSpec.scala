package com.peknight.jose.jwe

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.encryption.*
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwk.JsonWebKey.{EllipticCurveJsonWebKey, OctetSequenceJsonWebKey}
import com.peknight.security.cipher.AES
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class JsonWebEncryptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private val rawCek = ByteVector(4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
    212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207)
  private val plainText = "Live long and prosper."
  private val encodedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
  private val encodedCiphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
  private val encodedAuthenticationTag = "9hH0vgRfYgPnAHOd8stkvw"

  "A128CBC-HS256" should "succeed with testExampleEncryptFromJweAppendix2" in {
    val iv = ByteVector(3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101)
    val run =
      for
        plainTextBytes <- ByteVector.encodeUtf8(plainText).asError.eLiftET[IO]
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        contentEncryptionParts <- EitherT(`A128CBC-HS256`.encrypt[IO](rawCek, plainTextBytes, aad, Some(iv)).asError)
        ciphertext = Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext).value
        authenticationTag = Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag).value
      yield
        ciphertext == encodedCiphertext && authenticationTag == encodedAuthenticationTag
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A128CBC-HS256" should "succeed with testExampleDecryptFromJweAppendix2" in {
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
        decryptedText == plainText
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "A128CBC-HS256" should "succeed with testRoundTrip" in {
    val text = "I'm writing this test on a flight to Zurich"
    val run =
      for
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        plainTextBytes <- ByteVector.encodeUtf8(text).asError.eLiftET[IO]
        rawCek <- EitherT(randomBytes[IO](`A128CBC-HS256`.cekByteLength).asError)
        contentEncryptionParts <- EitherT(`A128CBC-HS256`.encrypt[IO](rawCek, plainTextBytes, aad, None).asError)
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
    val plainText = "The true sign of intelligence is not knowledge but imagination."
    val encodedHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
    val encodedCiphertext = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"
    val encodedAuthenticationTag = "XFBoMYUZodetZdvTiFvSkQ"
    val rawCek = ByteVector(177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91,
      112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252)
    val iv = ByteVector(227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219)
    val run =
      for
        plainTextBytes <- ByteVector.encodeUtf8(plainText).asError.eLiftET[IO]
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        contentEncryptionParts <- EitherT(A256GCM.encrypt[IO](rawCek, plainTextBytes, aad, Some(iv)).asError)
        ciphertext = Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext).value
        authenticationTag = Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag).value
        decrypted <- EitherT(A256GCM.decrypt[IO](rawCek, contentEncryptionParts.initializationVector,
          contentEncryptionParts.ciphertext, contentEncryptionParts.authenticationTag, aad))
      yield
        ciphertext == encodedCiphertext && authenticationTag == encodedAuthenticationTag && decrypted === plainTextBytes

    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "ECDH-ES" should "succeed" in {
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
        receiverPrivateKey <- receiverPrivateKey.toRight(OptionEmpty.label("receiverPrivateKey")).eLiftET[IO]
        ephemeralJwk <- decode[Id, EllipticCurveJsonWebKey](ephemeralJwkJson).eLiftET[IO]
        ephemeralPublicKey <- EitherT(ephemeralJwk.toPublicKey[IO]())
        ephemeralPrivateKey <- EitherT(ephemeralJwk.toPrivateKey[IO]())
        ephemeralPrivateKey <- ephemeralPrivateKey.toRight(OptionEmpty.label("ephemeralPrivateKey")).eLiftET[IO]
        apuBase <- Base64UrlNoPad.fromString(agreementPartyUInfo).eLiftET[IO]
        apvBase <- Base64UrlNoPad.fromString(agreementPartyVInfo).eLiftET[IO]
        apu <- apuBase.decode[Id].eLiftET[IO]
        apv <- apvBase.decode[Id].eLiftET[IO]
        contentEncryptionKeys <- EitherT(`ECDH-ES`.handleEncryptKey[IO](receiverPublicKey, A128GCM.blockSize,
          ephemeralPublicKey, ephemeralPrivateKey, Some(A128GCM), Some(apu), Some(apv)))
        contentEncryptionKey = Base64UrlNoPad.fromByteVector(contentEncryptionKeys.contentEncryptionKey).value
        decryptedKey <- EitherT(`ECDH-ES`.decryptKey[IO](receiverPrivateKey, contentEncryptionKeys.encryptedKey,
          A128GCM.blockSize, AES, None, Some(A128GCM), Some(ephemeralPublicKey), Some(apu), Some(apv)))
        key = Base64UrlNoPad.fromByteVector(ByteVector(decryptedKey.getEncoded)).value
      yield
        contentEncryptionKeys.encryptedKey.isEmpty && contentEncryptionKey == encodedContentEncryptionKey &&
          key == encodedContentEncryptionKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebEncryptionFlatSpec
