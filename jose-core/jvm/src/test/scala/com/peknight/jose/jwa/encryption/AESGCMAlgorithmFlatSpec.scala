package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwx.stringEncodeToBytes
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class AESGCMAlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

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
        plaintextBytes <- stringEncodeToBytes(plaintext).eLiftET[IO]
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

end AESGCMAlgorithmFlatSpec
