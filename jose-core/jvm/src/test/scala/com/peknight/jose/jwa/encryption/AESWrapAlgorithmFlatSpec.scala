package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class AESWrapAlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "A128KW" should "succeed with A128CBC-HS256" in {
    val rawCek = ByteVector(4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212,
      45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207)
    val jwkJson = "\n     {\"kty\":\"oct\",\n      \"k\":\"GawgguFyGrWKav7AX4VKUg\"\n     }"
    val encodedEncryptedKey = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    val run =
      for
        jwk <- decode[Id, OctetSequenceJsonWebKey](jwkJson).eLiftET[IO]
        key <- jwk.toKey.eLiftET[IO]
        contentEncryptionKeys <- EitherT(A128KW.encryptKey[IO](key, `A128CBC-HS256`.cekByteLength,
          `A128CBC-HS256`.cekAlgorithm, Some(rawCek)))
        encryptedKey = Base64UrlNoPad.fromByteVector(contentEncryptionKeys.encryptedKey).value
        cek <- EitherT(A128KW.decryptKey[IO](key, contentEncryptionKeys.encryptedKey,
          `A128CBC-HS256`.cekByteLength, `A128CBC-HS256`.cekAlgorithm))
      yield
        encryptedKey == encodedEncryptedKey && ByteVector(cek.getEncoded) === rawCek
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end AESWrapAlgorithmFlatSpec
