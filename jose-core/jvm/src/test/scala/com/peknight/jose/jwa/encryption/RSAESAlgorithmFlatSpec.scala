package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.either.*
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwe.{ContentEncryptionKeys, JsonWebEncryption}
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.jose.jwk.appendixA2
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.{AES, RSA}
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

  "RSAES" should "success with some round trips" in {
    val plaintext = "stuff"
    val tests = for alg <- RSAESAlgorithm.values yield
      for
        keyPair <- EitherT(RSA.keySizeGenerateKeyPair[IO](2048).asError)
        plaintextBytes <- ByteVector.encodeUtf8(plaintext).asError.eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](keyPair.getPublic, plaintextBytes, JoseHeader(Some(alg),
          Some(`A128CBC-HS256`))))
        jweCompact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](keyPair.getPrivate))
        decryptedPlaintext <- decrypted.decodeUtf8.asError.eLiftET[IO]
      yield
        decryptedPlaintext == plaintext
    tests.sequence.value.map(_.map(_.forall(identity)).getOrElse(false)).asserting(assert)
  }

  "RSAES" should "failed with some negative inputs" in {
    val jwkJson1 = "{\n        \"kty\": \"RSA\",\n        \"alg\": \"RSA1_5\",\n        \"use\": \"enc\",\n        \"n\": \"w2A4cbwOAK4ATnwXkGWereqv9dkEcgAGHc9g-cjo1HFeilYirvfD2Un2vQxW_6g2OKRPmmo46vMZFMYv_V57174j411y-NQlZGb7iFqMQADzo60VZ7vpvAX_NuxNGxYR-N2cBgvgqDiGAoO9ouNdhuHhxipTjGVfrPUpxmJtNPZpxsgxQWSpYCYMl304DD_5wWrnumNNIKOaVsAYmjFPV_wqxFCHbitPd1BG9SwXPk7wAHtXT6rYaUImS_OKaHkTO1OO0PNhd3-wJRNMCh_EGUwAghfWgFyAd20pQLZamamxgHvfL4-0hwuzndhHt0ye-gRVTtXDFEwABB--zwvlCw\",\n        \"e\": \"AQAB\",\n        \"kid\": \"rsa1_5\",\n        \"d\": \"EjMvbuDeyQ9sdeM3arscqgTXuWYq9Netui8sUHh3v_qDnQ1jE7t-4gny0y-IFy67RlGAHNlSTgixSG8h309i5_kNbMuyvx08EntJaS1OLVQpXhDskoo9vscsPBiNIj3PFMjIFQQcPG9vhGJzUu4tMzhtiME-oTB8VidMae-XTryPvozTu4rgfb4U7uauvLqESLz3A5xtzPnwNwqXAIlrdxU-MT_iln08on_QIF8afWUqCbsWWjEck_QDKLVpzh8VV9kkEVWwYfCFhHBwS-fgGJJTE3gK4HwOokydMtH95Dzj47MA2pLe600l7ioyGSPltcv967NtOpxMPM5ro751KQ\",\n        \"p\": \"-F1u3NAMWPu1TIuvIywIjh5fuiA3AVKLgS6Fw_hAi3M9c3T7E1zNJZuHgQExJEu06ZPfzye9m7taDzh-Vw4VGDED_MZedsE2jEsWa9EKeq3bZVf5j81FLCHH8BicFqrPjvoVUC35wrl9SGJzaOa7KXxD2jW22umYjJS_kcopvf0\",\n        \"q\": \"yWHG7jHqvfqT8gfhIlxpMbeJ02FrWIkgJC-zOJ26wXC6oxPeqhqEO7ulGqZPngNDdSGgWcQ7noGEU8O4MA9V3yhl91TFZy8unox0sGe0jDMwtxm3saXtTsjTE7FBxzcR0PubfyGiS0fJqQcj8oJSWzZPkUshzZ8rF3jTLc8UWac\",\n        \"dp\": \"Va9WWhPkzqY4TCo8x_OfF_jeqcYHdAtYWb8FIzD4g6PEZZrMLEft9rWLsDQLEiyUQ6lio4NgZOPkFDA3Vi1jla8DYyfE20-ZVBlrqNK7vMtST8pkLPpyjOEyq2CyKRfQ99DLnZfe_RElad2dV2mS1KMsfZHeffPtT0LaPJ_0erk\",\n        \"dq\": \"M8rA1cviun9yg0HBhgvMRiwU91dLu1Zw_L2D02DFgjCS35QhpQ_yyEYHPWZefZ4LQFmoms2cI7TdqolgmoOnKyCBsO2NY29AByjKbgAN8CzOL5kepEKvWJ7PonXpG-ou29eJ81VcHw5Ub_NVLG6V7b13E0AGbpKsC3pYnaRvcGs\",\n        \"qi\": \"8zIqISvddJYC93hP0sKkdHuVd-Mes_gsbi8xqSFYGqc-wSU12KjzHnZmBuJl_VTGy9CO9W4K2gejr588a3Ozf9U5hx9qCVkV0_ttxHcTRem5sFPe9z-HkQE5IMW3SdmL1sEcvkzD7z8QhcHRpp5aMptfuwnxBPY8U449_iNgXd4\"\n      }"
    val jwkJson2 = "{\n        \"alg\": \"RSA-OAEP\",\n        \"use\": \"enc\",\n        \"n\": \"kqGboBfAWttWPCA-0cGRgsY6SaYoIARt0B_PkaEcIq9HPYNdu9n6UuWHuuTHrjF_ZoQW97r5HaAorNvrMEGTGdxCHZdEtkHvNVVmrtxTBLiQCbCozXhFoIrVcr3qUBrdGnNn_M3jJi7Wg7p_-x62nS5gNG875oyheRkutHsQXikFZwsN3q_TsPNOVlCiHy8mxzaFTUQGm-X8UYexFyAivlDSjgDJLAZSWfxd7k9Gxuwa3AUfQqQcVcegmgKGCaErQ3qQbh1x7WB6iopE3_-GZ8HMAVtR9AmrVscqYsnjhaCehfAI0iKKs8zXr8tISc0ORbaalrkk03H1ZrsEnDKEWQ\",\n        \"e\": \"AQAB\",\n        \"d\": \"YsfIRYN6rDqSz5KRf1E9q7HK1o6-_UK-j7S-asb0Y1FdVs1GuiRQhMPoOjmhY3Io93EI3_7vj8uzWzAUMsAaTxOY3sJnIbktYuqTcD0xGD8VmdGPBkx963db8B6M2UYfqZARf7dbzP9EuB1N1miMcTsqyGgfHGOk7CXQ1vkIv8Uww38KMtEdJ3iB8r-f3qcu-UJjE7Egw9CxKOMjArOXxZEr4VnoIXrImrcTxBfjdY8GbzXGATiPQLur5GT99ZDW78falsir-b5Ean6HNyOeuaJuceT-yjgCXn57Rd3oIHD94CrjNtjBusoLdjbr489L8K9ksCh1gynzLGkeeWgVGQ\",\n        \"p\": \"0xalbl1PJbSBGD4XOjIYJLwMYyHMiM06SBauMGzBfCask5DN5jH68Kw1yPS4wkLpx4ltGLuy0X5mMaZzrSOkBGb27-NizBgB2-L279XotznWeh2jbF05Kqzkoz3VaX_7dRhCHEhOopMQh619hA1bwaJyW1k8aNlLPTl3BotkP4M\",\n        \"q\": \"sdQsQVz3tI7hmisAgiIjppOssEnZaZO0ONeRRDxBHGLe3BCo1FJoMMQryOAlglayjQnnWjQ-BpwUpa0r9YQhVLweoNEIig6Beph7iYRZgOHEiiTTgUIGgXAL6xhsby1PueUfT0xsN1Y7qt5f5EwOfu7tnFqNyJXIp9W1NQgU6fM\",\n        \"dp\": \"kEpEnuJNfdqa-_VFb1RayJF6bjDmXQTcN_a47wUIZVMSWHR9KkMz41v0D_-oY7HVl73Kw0NagnVCaeH75HgeX5v6ZBQsrpIigynr3hl8T_LLNwIXebVnpFI2n5de0BTZ0DraxfZvOhYJEJV43NE8zWm7fdHLx2fxVFJ5mBGkXv0\",\n        \"dq\": \"U_xJCnXF51iz5AP7MXq-K6YDIR8_t0UzEMV-riNm_OkVKAoWMnDZFG8R3sU98djQaxwKT-fsg2KjvbuTz1igBUzzijAvQESpkiUB82i2fNAj6rqJybpNKESq3FWkoL1dsgYsS19knJ31gDWWRFRHZFujjPyXiexz4BBmjK1Mc1E\",\n        \"qi\": \"Uvb84tWiJF3fB-U9wZSPi7juGgrzeXS_LYtf5fcdV0fZg_h_5nSVpXyYyQ-PK218qEC5MlDkaHKRD9wBOe_eU_zJTNoXzB2oAcgl2MapBWUMytbiF84ghP_2K9UD63ZVsyrorSZhmsJIBBuqQjrmk0tIdpMdlMxLYhrbYwFxUqc\",\n        \"kid\": \"kid-rsa-enc-oaep\",\n        \"kty\": \"RSA\"\n      }"
    // The first ciphertext below contains an invalid PKCS #1 padding.
    val first = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.ksmeZ6dBbP0UfDEaLXlqPl2XDaAA29kGlKtDb89x-4xN5-A6bx2umI_ToHK2GadzxUOgKROCACYb6rmKsqsQCOZaBsnq_4mDII1W0pja7Lz4zTnr7R3O4kALg4zXqG-gSlcDA7k1NgkpMDS15PjMmADqyqxbxQsXdfjstN324iqdvYGh6NsckkfTSWxDVAqiSR9fW8PsIbo3uSMokNaC-f64CDWIB9AsCxhF-3mnFbxXNxw7JE0upOgG4enQ8kZkwi_v54HBqAau1YNW7gPhFV8ElTQ71J6aHB3dja23lbWdaJmrK6PJE7gEeZmUbFkSYmuyzRUS-NGfXA23fYv5JQ.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ"
    // The second ciphertext below contains valid PKCS #1 padding, but the size of the encoded key is incorrect.
    val second = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.oyVTmkyoChxFtyCtiKhv8OpBJcV6C6s_gMFSSRJBNStpdHPzq2YmroTfXGj1J1plFG4BBQwIZtdt6rIS6YkCvTLGqP1hds9CAO1a_bgRyoAVuOVvH2vmz5U2r74_SRbAzD35M7yZ_tSnnEdMFlHMFbf5uNwmgArrtPgh0V5OLn5i4XIc154FLTiQlvAEhUxiPuYBkm_1GBiYEH4JjP2RKXAUx_TxAVwPsOfIPAVrO0Ev_nvdtVLCE-uOn8WQbxh4wwOztaXOV1HIaPrl7HN-YtDOA840QUHm97ZZLAPRgLzGlkMI0ZS8QkYdb9_FT3KMbNu60nBKEniv2uhBdIhM9g.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ"
    // RSA-OAEP w/ the alg header changed RSA1_5
    val third = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.CuUuY9PH2wWjuLXd5O9LLFanwyt5-y-NzEpy9rC3A63tFsvdp8GWP1kRt1d3zd0bGqakwls623VQxzxqQ25j5gdHh8dKMl67xTLHt1Qlg36nI9Ukn7syq25VrzfrRRwy0k7isqMncHpzuBQlmfzPrszW7d13z7_ex0Uha869RaP-W2NNBfHYw26xIXcCSVIPg8jTLA7h6QmOetEej-NXXcWrRKQgBRapYy4iWrij9Vr3JzAGSHVtIID74tFOm01FdJj4s1M4IXegDbvAdQb6Vao1Ln5GolnTki4IGvH5FDssDHz6MS2JG5QBcITzfuXU81vDC00xzNEuMat0AngmOw.UjPQbnakkZYUdoDa.vcbS.WQ_bOPiGKjPSq-qyGOIfjA"
    val run =
      for
        jwk1 <- decode[Id, RSAJsonWebKey](jwkJson1).eLiftET[IO]
        privateKey1 <- EitherT(jwk1.toPrivateKey[IO]())
        firstJwe <- JsonWebEncryption.parse(first).asError.eLiftET[IO]
        firstFlag <- EitherT(firstJwe.decrypt[IO](privateKey1).map(_.isLeft.asRight))
        secondJwe <- JsonWebEncryption.parse(second).asError.eLiftET[IO]
        secondFlag <- EitherT(secondJwe.decrypt[IO](privateKey1).map(_.isLeft.asRight))
        jwk2 <- decode[Id, RSAJsonWebKey](jwkJson2).eLiftET[IO]
        privateKey2 <- EitherT(jwk2.toPrivateKey[IO]())
        thirdJwe <- JsonWebEncryption.parse(third).asError.eLiftET[IO]
        header <- thirdJwe.getUnprotectedHeader.eLiftET[IO]
        _ = println(header)
        thirdFlag <- EitherT(thirdJwe.decrypt[IO](privateKey2).map(_.isRight.asRight))
      yield
        firstFlag && secondFlag && thirdFlag
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end RSAESAlgorithmFlatSpec
