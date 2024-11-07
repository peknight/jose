package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.jose.jwk.appendixA2
import com.peknight.security.cipher.AES
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class RSAESAlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "RSA1_5" should "success with jwe example A2" in {
    val encodedEncryptedKey = "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH" +
      "5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNP" +
      "ccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cF" +
      "PgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
    val cekBytes = ByteVector(4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212,
      45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207)
    val alg = RSA1_5
    val enc = `A128CBC-HS256`
    val run =
      for
        encryptedKeyBase <- Base64UrlNoPad.fromString(encodedEncryptedKey).eLiftET[IO]
        encryptedKeyBytes <- encryptedKeyBase.decode[Id].eLiftET[IO]
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        key <- EitherT(alg.decryptKey[IO](privateKey, encryptedKeyBytes, enc.cekByteLength, enc.cekAlgorithm))
      yield
        ByteVector(key.getEncoded) === cekBytes
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSA1_5" should "success with round trip" in {
    val run =
      for
        publicKey <- EitherT(appendixA2.toPublicKey[IO]())
        privateKey <- EitherT(appendixA2.toPrivateKey[IO]())
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, _, _, _, _, _) <- EitherT(RSA1_5.encryptKey[IO](
          publicKey, 16, AES))
        key  <- EitherT(RSA1_5.decryptKey[IO](privateKey, encryptedKey, 16, AES))
      yield
        ByteVector(key.getEncoded) === contentEncryptionKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

end RSAESAlgorithmFlatSpec
