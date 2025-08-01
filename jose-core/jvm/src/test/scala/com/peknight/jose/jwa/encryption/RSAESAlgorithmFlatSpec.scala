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
import com.peknight.error.syntax.applicativeError.asET
import com.peknight.jose.jwe.{ContentEncryptionKeys, JsonWebEncryption}
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.jose.jwk.{appendixA1, appendixA2}
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.{AES, RSA}
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class RSAESAlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private val jwkJson = "{\"kty\":\"RSA\",\"n\":\"2cQJH1f6yF9DcGa8Cmbnhn4LHLs5L6kNb2rxkrNFZArJLRaKvaC3tMCKZ8ZgIpO9bV" +
    "MPx5UMjJoaf7p9O5BSApVqA2J10fUbdSIomCcDwvGo0eyhty0DILLWTMXzGEVM3BXzuJQoeDkuUCXXcCwA4Msyyd2OHVu-pB2OrGv6fcjHwjINt" +
    "y3UoKm08lCvAevBKHsuA-FFwQII9bycvRx5wRqFUjdMAyiOmLYBHBaJSi11g3HVexMcb29v14PSlVzdGUMN8oboa-zcIyaPrIiczLqAkSXQNdEF" +
    "HrjsJHfFeNMfOblLM7icKN_tyWujYeItt4kqUIimPn5dHjwgcQYE7w\",\"e\":\"AQAB\",\"d\":\"dyUz3ItVceX1Tv1WqtZMnKA_0jN5gWM" +
    "cL7ayf5JISAlCssGfnUre2C10TH0UQjbVMIh-nLMnD5KNJw9Qz5MR28oGG932Gq7hm__ZeA34l-OCe4DdpgwhpvVSHOU9MS1RdSUpmPavAcA_X6" +
    "ikrAHXZSaoHhxzUgrNTpvBYQMfJUv_492fStIseQ9rwAMOpCWOiWMZOQm3KJVTLLunXdKf_UxmzmKXYKYZWke3AWIzUqnOfqIjfDTMunF4UWU0z" +
    "KlhcsaQNmYMVrJGajD1bJdy_dbUU3LE8sx-bdkUI6oBk-sFtTTVyVdQcetG9kChJ5EnY5R6tt_4_xFG5kxzTo6qaQ\",\"p\":\"7yQmgE60SL7" +
    "QrXpAJhChLgKnXWi6C8tVx1lA8FTpphpLaCtK-HbgBVHCprC2CfaM1mxFJZahxgFjC9ehuV8OzMNyFs8kekS82EsQGksi8HJPxyR1fU6ATa36og" +
    "PG0nNaqm3EDmYyjowhntgBz2OkbFAsTMHTdna-pZBRJa9lm5U\",\"q\":\"6R4dzo9LwHLO73EMQPQsmwXjVOvAS5W6rgQ-BCtMhec_QosAXIV" +
    "E3AGyfweqZm6rurXCVFykDLwJ30GepLQ8nTlzeV6clx0x70saGGKKVmCsHuVYWwgIRyJTrt4SX29NQDZ_FE52NlO3OhPkj1ExSk_pGMqGRFd26K" +
    "8g0jJsXXM\",\"dp\":\"VByn-hs0qB2Ncmb8ZycUOgWu7ljmjz1up1ZKU_3ZzJWVDkej7-6H7vcJ-u1OqgRxFv4v9_-aWPWl68VlWbkIkJbx6v" +
    "niv6qrrXwBZu4klOPwEYBOXsucrzXRYOjpJp5yNl2zRslFYQQC00bwpAxNCdfNLRZDlXhAqCUxlYqyt10\",\"dq\":\"MJFbuGtWZvQEdRJicS" +
    "3uFSY25LxxRc4eJJ8xpIC44rT5Ew4Otzf0zrlzzM92Cv1HvhCcOiNK8nRCwkbTnJEIh-EuU70IdttYSfilqSruk2x0r8Msk1qrDtbyBF60CToRK" +
    "C2ycDKgolTyuaDnX4yU7lyTvdyD-L0YQwYpmmFy_k0\",\"qi\":\"vy7XCwZ3jyMGik81TIZDAOQKC8FVUc0TG5KVYfti4tgwzUqFwtuB8Oc1c" +
    "tCKRbE7uZUPwZh4OsCTLqIvqBQda_kaxOxo5EF7iXj6yHmZ2s8P_Z_u3JLuh-oAT_6kmbLx6CAO0DbtKtxp24Ivc1hDfqSwWORgN1AOrSRCmE3n" +
    "wxg\"}"
  private val examplePayload = "Well, as of this moment, they're on DOUBLE SECRET PROBATION!"

  "RSA1_5" should "succeed with jwe example A2" in {
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

  "RSA1_5" should "succeed with round trip" in {
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

  "RSAES" should "succeed with some round trips" in {
    val plaintext = "stuff"
    val tests = for alg <- RSAESAlgorithm.values yield
      for
        keyPair <- RSA.keySizeGenerateKeyPair[IO](2048).asET
        jwe <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(alg), Some(`A128CBC-HS256`)), plaintext,
          keyPair.getPublic))
        jweCompact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCompact).eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](keyPair.getPrivate))
      yield
        decrypted == plaintext
    tests.sequence.value.map(_.map(_.forall(identity)).getOrElse(false)).asserting(assert)
  }

  "RSAES" should "failed with some negative inputs" in {
    val jwkJson1 = "{\n        \"kty\": \"RSA\",\n        \"alg\": \"RSA1_5\",\n        \"use\": \"enc\",\n        " +
      "\"n\": \"w2A4cbwOAK4ATnwXkGWereqv9dkEcgAGHc9g-cjo1HFeilYirvfD2Un2vQxW_6g2OKRPmmo46vMZFMYv_V57174j411y-NQlZGb7" +
      "iFqMQADzo60VZ7vpvAX_NuxNGxYR-N2cBgvgqDiGAoO9ouNdhuHhxipTjGVfrPUpxmJtNPZpxsgxQWSpYCYMl304DD_5wWrnumNNIKOaVsAYm" +
      "jFPV_wqxFCHbitPd1BG9SwXPk7wAHtXT6rYaUImS_OKaHkTO1OO0PNhd3-wJRNMCh_EGUwAghfWgFyAd20pQLZamamxgHvfL4-0hwuzndhHt0" +
      "ye-gRVTtXDFEwABB--zwvlCw\",\n        \"e\": \"AQAB\",\n        \"kid\": \"rsa1_5\",\n        \"d\": \"EjMvbuD" +
      "eyQ9sdeM3arscqgTXuWYq9Netui8sUHh3v_qDnQ1jE7t-4gny0y-IFy67RlGAHNlSTgixSG8h309i5_kNbMuyvx08EntJaS1OLVQpXhDskoo9" +
      "vscsPBiNIj3PFMjIFQQcPG9vhGJzUu4tMzhtiME-oTB8VidMae-XTryPvozTu4rgfb4U7uauvLqESLz3A5xtzPnwNwqXAIlrdxU-MT_iln08o" +
      "n_QIF8afWUqCbsWWjEck_QDKLVpzh8VV9kkEVWwYfCFhHBwS-fgGJJTE3gK4HwOokydMtH95Dzj47MA2pLe600l7ioyGSPltcv967NtOpxMPM" +
      "5ro751KQ\",\n        \"p\": \"-F1u3NAMWPu1TIuvIywIjh5fuiA3AVKLgS6Fw_hAi3M9c3T7E1zNJZuHgQExJEu06ZPfzye9m7taDzh" +
      "-Vw4VGDED_MZedsE2jEsWa9EKeq3bZVf5j81FLCHH8BicFqrPjvoVUC35wrl9SGJzaOa7KXxD2jW22umYjJS_kcopvf0\",\n        \"q" +
      "\": \"yWHG7jHqvfqT8gfhIlxpMbeJ02FrWIkgJC-zOJ26wXC6oxPeqhqEO7ulGqZPngNDdSGgWcQ7noGEU8O4MA9V3yhl91TFZy8unox0sGe" +
      "0jDMwtxm3saXtTsjTE7FBxzcR0PubfyGiS0fJqQcj8oJSWzZPkUshzZ8rF3jTLc8UWac\",\n        \"dp\": \"Va9WWhPkzqY4TCo8x_" +
      "OfF_jeqcYHdAtYWb8FIzD4g6PEZZrMLEft9rWLsDQLEiyUQ6lio4NgZOPkFDA3Vi1jla8DYyfE20-ZVBlrqNK7vMtST8pkLPpyjOEyq2CyKRf" +
      "Q99DLnZfe_RElad2dV2mS1KMsfZHeffPtT0LaPJ_0erk\",\n        \"dq\": \"M8rA1cviun9yg0HBhgvMRiwU91dLu1Zw_L2D02DFgj" +
      "CS35QhpQ_yyEYHPWZefZ4LQFmoms2cI7TdqolgmoOnKyCBsO2NY29AByjKbgAN8CzOL5kepEKvWJ7PonXpG-ou29eJ81VcHw5Ub_NVLG6V7b1" +
      "3E0AGbpKsC3pYnaRvcGs\",\n        \"qi\": \"8zIqISvddJYC93hP0sKkdHuVd-Mes_gsbi8xqSFYGqc-wSU12KjzHnZmBuJl_VTGy9" +
      "CO9W4K2gejr588a3Ozf9U5hx9qCVkV0_ttxHcTRem5sFPe9z-HkQE5IMW3SdmL1sEcvkzD7z8QhcHRpp5aMptfuwnxBPY8U449_iNgXd4\"\n" +
      "      }"
    val jwkJson2 = "{\n        \"alg\": \"RSA-OAEP\",\n        \"use\": \"enc\",\n        \"n\": \"kqGboBfAWttWPCA-0" +
      "cGRgsY6SaYoIARt0B_PkaEcIq9HPYNdu9n6UuWHuuTHrjF_ZoQW97r5HaAorNvrMEGTGdxCHZdEtkHvNVVmrtxTBLiQCbCozXhFoIrVcr3qUB" +
      "rdGnNn_M3jJi7Wg7p_-x62nS5gNG875oyheRkutHsQXikFZwsN3q_TsPNOVlCiHy8mxzaFTUQGm-X8UYexFyAivlDSjgDJLAZSWfxd7k9Gxuw" +
      "a3AUfQqQcVcegmgKGCaErQ3qQbh1x7WB6iopE3_-GZ8HMAVtR9AmrVscqYsnjhaCehfAI0iKKs8zXr8tISc0ORbaalrkk03H1ZrsEnDKEWQ\"" +
      ",\n        \"e\": \"AQAB\",\n        \"d\": \"YsfIRYN6rDqSz5KRf1E9q7HK1o6-_UK-j7S-asb0Y1FdVs1GuiRQhMPoOjmhY3I" +
      "o93EI3_7vj8uzWzAUMsAaTxOY3sJnIbktYuqTcD0xGD8VmdGPBkx963db8B6M2UYfqZARf7dbzP9EuB1N1miMcTsqyGgfHGOk7CXQ1vkIv8Uw" +
      "w38KMtEdJ3iB8r-f3qcu-UJjE7Egw9CxKOMjArOXxZEr4VnoIXrImrcTxBfjdY8GbzXGATiPQLur5GT99ZDW78falsir-b5Ean6HNyOeuaJuc" +
      "eT-yjgCXn57Rd3oIHD94CrjNtjBusoLdjbr489L8K9ksCh1gynzLGkeeWgVGQ\",\n        \"p\": \"0xalbl1PJbSBGD4XOjIYJLwMYy" +
      "HMiM06SBauMGzBfCask5DN5jH68Kw1yPS4wkLpx4ltGLuy0X5mMaZzrSOkBGb27-NizBgB2-L279XotznWeh2jbF05Kqzkoz3VaX_7dRhCHEh" +
      "OopMQh619hA1bwaJyW1k8aNlLPTl3BotkP4M\",\n        \"q\": \"sdQsQVz3tI7hmisAgiIjppOssEnZaZO0ONeRRDxBHGLe3BCo1FJ" +
      "oMMQryOAlglayjQnnWjQ-BpwUpa0r9YQhVLweoNEIig6Beph7iYRZgOHEiiTTgUIGgXAL6xhsby1PueUfT0xsN1Y7qt5f5EwOfu7tnFqNyJXI" +
      "p9W1NQgU6fM\",\n        \"dp\": \"kEpEnuJNfdqa-_VFb1RayJF6bjDmXQTcN_a47wUIZVMSWHR9KkMz41v0D_-oY7HVl73Kw0NagnV" +
      "CaeH75HgeX5v6ZBQsrpIigynr3hl8T_LLNwIXebVnpFI2n5de0BTZ0DraxfZvOhYJEJV43NE8zWm7fdHLx2fxVFJ5mBGkXv0\",\n        " +
      "\"dq\": \"U_xJCnXF51iz5AP7MXq-K6YDIR8_t0UzEMV-riNm_OkVKAoWMnDZFG8R3sU98djQaxwKT-fsg2KjvbuTz1igBUzzijAvQESpkiU" +
      "B82i2fNAj6rqJybpNKESq3FWkoL1dsgYsS19knJ31gDWWRFRHZFujjPyXiexz4BBmjK1Mc1E\",\n        \"qi\": \"Uvb84tWiJF3fB-" +
      "U9wZSPi7juGgrzeXS_LYtf5fcdV0fZg_h_5nSVpXyYyQ-PK218qEC5MlDkaHKRD9wBOe_eU_zJTNoXzB2oAcgl2MapBWUMytbiF84ghP_2K9U" +
      "D63ZVsyrorSZhmsJIBBuqQjrmk0tIdpMdlMxLYhrbYwFxUqc\",\n        \"kid\": \"kid-rsa-enc-oaep\",\n        \"kty\":" +
      " \"RSA\"\n      }"
    // The first ciphertext below contains an invalid PKCS #1 padding.
    val first = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.ksmeZ6dBbP0UfDEaLXlqPl2XDaAA29kGlKtDb89x-4xN5-A6bx2umI_" +
      "ToHK2GadzxUOgKROCACYb6rmKsqsQCOZaBsnq_4mDII1W0pja7Lz4zTnr7R3O4kALg4zXqG-gSlcDA7k1NgkpMDS15PjMmADqyqxbxQsXdfjs" +
      "tN324iqdvYGh6NsckkfTSWxDVAqiSR9fW8PsIbo3uSMokNaC-f64CDWIB9AsCxhF-3mnFbxXNxw7JE0upOgG4enQ8kZkwi_v54HBqAau1YNW7" +
      "gPhFV8ElTQ71J6aHB3dja23lbWdaJmrK6PJE7gEeZmUbFkSYmuyzRUS-NGfXA23fYv5JQ.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHi" +
      "aqhiQ"
    // The second ciphertext below contains valid PKCS #1 padding, but the size of the encoded key is incorrect.
    val second = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.oyVTmkyoChxFtyCtiKhv8OpBJcV6C6s_gMFSSRJBNStpdHPzq2Ymro" +
      "TfXGj1J1plFG4BBQwIZtdt6rIS6YkCvTLGqP1hds9CAO1a_bgRyoAVuOVvH2vmz5U2r74_SRbAzD35M7yZ_tSnnEdMFlHMFbf5uNwmgArrtPg" +
      "h0V5OLn5i4XIc154FLTiQlvAEhUxiPuYBkm_1GBiYEH4JjP2RKXAUx_TxAVwPsOfIPAVrO0Ev_nvdtVLCE-uOn8WQbxh4wwOztaXOV1HIaPrl" +
      "7HN-YtDOA840QUHm97ZZLAPRgLzGlkMI0ZS8QkYdb9_FT3KMbNu60nBKEniv2uhBdIhM9g.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEH" +
      "iaqhiQ"
    // RSA-OAEP w/ the alg header changed RSA1_5
    val third = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.CuUuY9PH2wWjuLXd5O9LLFanwyt5-y-NzEpy9rC3A63tFsvdp8GWP1k" +
      "Rt1d3zd0bGqakwls623VQxzxqQ25j5gdHh8dKMl67xTLHt1Qlg36nI9Ukn7syq25VrzfrRRwy0k7isqMncHpzuBQlmfzPrszW7d13z7_ex0Uh" +
      "a869RaP-W2NNBfHYw26xIXcCSVIPg8jTLA7h6QmOetEej-NXXcWrRKQgBRapYy4iWrij9Vr3JzAGSHVtIID74tFOm01FdJj4s1M4IXegDbvAd" +
      "Qb6Vao1Ln5GolnTki4IGvH5FDssDHz6MS2JG5QBcITzfuXU81vDC00xzNEuMat0AngmOw.UjPQbnakkZYUdoDa.vcbS.WQ_bOPiGKjPSq-qyG" +
      "OIfjA"
    val run =
      for
        jwk1 <- decode[Id, RSAJsonWebKey](jwkJson1).eLiftET[IO]
        privateKey1 <- EitherT(jwk1.toPrivateKey[IO]())
        firstJwe <- JsonWebEncryption.parse(first).eLiftET[IO]
        firstFlag <- EitherT(firstJwe.decrypt[IO](privateKey1).map(_.isLeft.asRight))
        secondJwe <- JsonWebEncryption.parse(second).eLiftET[IO]
        secondFlag <- EitherT(secondJwe.decrypt[IO](privateKey1).map(_.isLeft.asRight))
        jwk2 <- decode[Id, RSAJsonWebKey](jwkJson2).eLiftET[IO]
        privateKey2 <- EitherT(jwk2.toPrivateKey[IO]())
        thirdJwe <- JsonWebEncryption.parse(third).eLiftET[IO]
        header <- thirdJwe.getMergedHeader.eLiftET[IO]
        thirdFlag <- EitherT(thirdJwe.decrypt[IO](privateKey2).map(_.isRight.asRight))
      yield
        firstFlag && secondFlag && thirdFlag
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSA-OAEP" should "succeed with jwe example A1" in {
    // only the key encryption part from
    // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-25#appendix-A.1
    val encodedEncryptedKey = "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr0" +
      "5kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmq" +
      "gfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_Z" +
      "T2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg"
    val cekBytes = ByteVector(177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110,
      91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252)
    val run =
      for
        encryptedKeyBase <- Base64UrlNoPad.fromString(encodedEncryptedKey).eLiftET[IO]
        encryptedKeyBytes <- encryptedKeyBase.decode[Id].eLiftET[IO]
        privateKey <- EitherT(appendixA1.toPrivateKey[IO]())
        key <- EitherT(`RSA-OAEP`.decryptKey[IO](privateKey, encryptedKeyBytes, 32, AES))
      yield
        ByteVector(key.getEncoded) === cekBytes
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSA-OAEP" should "succeed with round trip" in {
    val run =
      for
        publicKey <- EitherT(appendixA1.toPublicKey[IO]())
        ContentEncryptionKeys(cek, encryptedKey, _, _, _, _, _) <- EitherT(`RSA-OAEP`.encryptKey[IO](publicKey, 16, AES))
        privateKey <- EitherT(appendixA1.toPrivateKey[IO]())
        key <- EitherT(`RSA-OAEP`.decryptKey[IO](privateKey, encryptedKey, 16, AES))
      yield
        ByteVector(key.getEncoded) === cek
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSA-OAEP-256" should "succeed with round trip" in {
    val run =
      for
        jwk <- decode[Id, RSAJsonWebKey](jwkJson).eLiftET[IO]
        publicKey <- EitherT(jwk.toPublicKey[IO]())
        jwe <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(`RSA-OAEP-256`), Some(`A128CBC-HS256`)),
          examplePayload, publicKey))
        jweCompact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCompact).eLiftET[IO]
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        decrypted <- EitherT(jwe.decryptString[IO](privateKey))
      yield
        decrypted == examplePayload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSA-OAEP-256" should "succeed with working example from mail list" in {
    // http://www.ietf.org/mail-archive/web/jose/current/msg04131.html
    // okay it's my own example but it's all I've got right now
    val cs = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
      "fL5IL5cMCjjU9G9_ZjsD2XO0HIwTOwbVwulcZVw31_rx2qTcHzbYhIvrvbcVLTfJzn8xbQ3UEL442ZgZ1PcFYKENYePXiEyvYxPN8dmvj_OfL" +
      "SJDEqR6kvwOb6nghGtxfzdB_VRvFt2eehbCA3gWpiOYHHvSTFdBPGx2KZHQisLz3oZR8EWiZ1woEpHy8a7FoQ2zzuDlZEJQOUrh09b_EJxmcE" +
      "2jL6wmEtgabyxy3VgWg3GqSPUISlJZV9HThuVJezzktJdpntRDnAPUqjc8IwByGpMleIQcPuBUseRRPr_OsroOJ6eTl5DuFCmBOKb-eNNw5v-" +
      "GEcVYr1w7X9oXoA." +
      "0frdIwx8P8UAzh1s9_PgOA." +
      "RAzILH0xfs0yxzML1CzzGExCfE2_wzWKs0FVuXfM8R5H68yTqTbqIqRCp2feAH5GSvluzmztk2_CkGNSjAyoaw." +
      "4nMUXOgmgWvM-08tIZ-h5w"
    val run =
      for
        jwk <- decode[Id, RSAJsonWebKey](jwkJson).eLiftET[IO]
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        jwe <- JsonWebEncryption.parse(cs).eLiftET[IO]
        header <- jwe.getMergedHeader.eLiftET[IO]
        decrypted <- EitherT(jwe.decryptString[IO](privateKey))
      yield
        decrypted == examplePayload
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end RSAESAlgorithmFlatSpec
