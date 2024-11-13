package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwe.{ContentEncryptionKeys, ContentEncryptionParts, JsonWebEncryption}
import com.peknight.jose.jwk.{JsonWebKey, KeyId, KeyType, PublicKeyUseType}
import com.peknight.jose.jwx.{JoseHeader, decodeOption, fromBase, toBytes}
import com.peknight.security.cipher.AES
import com.peknight.security.key.secret.PBKDF2
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class PBES2AlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  private val minimumIterationCount = 1000
  private val minimumSaltByteLength: Int = 8

  private val password = "Thus from my lips, by yours, my sin is purged."

  private val cs = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk2LCJl" +
    "bmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ." +
    "TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA." +
    "Ye9j1qs22DmRSAddIh-VnA." +
    "AwhB8lxrlKjFn02LGWEqg27H4Tg9fyZAbFv3p5ZicHpj64QyHC44qqlZ3JEmnZTgQowIqZJ13jbyHB8LgePiqUJ1hf6M2HPLgzw8L-mEeQ0jvDU" +
    "TrE07NtOerBk8bwBQyZ6g0kQ3DEOIglfYxV8-FJvNBYwbqN1Bck6d_i7OtjSHV-8DIrp-3JcRIe05YKy3Oi34Z_GOiAc1EK21B11c_AE11PII_w" +
    "vvtRiUiG8YofQXakWd1_O98Kap-UgmyWPfreUJ3lJPnbD4Ve95owEfMGLOPflo2MnjaTDCwQokoJ_xplQ2vNPz8iguLcHBoKllyQFJL2mOWBwqh" +
    "Bo9Oj-O800as5mmLsvQMTflIrIEbbTMzHMBZ8EFW9fWwwFu0DWQJGkMNhmBZQ-3lvqTc-M6-gWA6D8PDhONfP2Oib2HGizwG1iEaX8GRyUpfLul" +
    "jCLIe1DkGOewhKuKkZh04DKNM5Nbugf2atmU9OP0Ldx5peCUtRG1gMVl7Qup5ZXHTjgPDr5b2N731UooCGAUqHdgGhg0JVJ_ObCTdjsH4CF1SJs" +
    "dUhrXvYx3HJh2Xd7CwJRzU_3Y1GxYU6-s3GFPbirfqqEipJDBTHpcoCmyrwYjYHFgnlqBZRotRrS95g8F95bRXqsaDY7UgQGwBQBwy665d0zpvT" +
    "asvfXf_c0MWAl-neFaKOW_Px6g4EUDjG1GWSXV9cLStLw_0ovdApDIFLHYHePyagyHjouQUuGiq7BsYwYrwaF06tgB8hV8omLNfMEmDPJaZUzMu" +
    "Hw6tBDwGkzD-tS_ub9hxrpJ4UsOWnt5rGUyoN2N_c1-TQlXxm5oto14MxnoAyBQBpwIEgSH3Y4ZhwKBhHPjSo0cdwuNdYbGPpb-YUvF-2NZzODi" +
    "Q1OvWQBRHSbPWYz_xbGkgD504LRtqRwCO7CC_CyyURi1sEssPVsMJRX_U4LFEOc82TiDdqjKOjRUfKK5rqLi8nBE9soQ0DSaOoFQZiGrBrqxDsN" +
    "YiAYAmxxkos-i3nX4qtByVx85sCE5U_0MqG7COxZWMOPEFrDaepUV-cOyrvoUIng8i8ljKBKxETY2BgPegKBYCxsAUcAkKamSCC9AiBxA0UOHyh" +
    "TqtlvMksO7AEhNC2-YzPyx1FkhMoS4LLe6E_pFsMlmjA6P1NSge9C5G5tETYXGAn6b1xZbHtmwrPScro9LWhVmAaA7_bxYObnFUxgWtK4vzzQBj" +
    "ZJ36UTk4OTB-JvKWgfVWCFsaw5WCHj6Oo4jpO7d2yN7WMfAj2hTEabz9wumQ0TMhBduZ-QON3pYObSy7TSC1vVme0NJrwF_cJRehKTFmdlXGVld" +
    "PxZCplr7ZQqRQhF8JP-l4mEQVnCaWGn9ONHlemczGOS-A-wwtnmwjIB1V_vgJRf4FdpV-4hUk4-QLpu3-1lWFxrtZKcggq3tWTduRo5_QebQbUU" +
    "T_VSCgsFcOmyWKoj56lbxthN19hq1XGWbLGfrrR6MWh23vk01zn8FVwi7uFwEnRYSafsnWLa1Z5TpBj9GvAdl2H9NHwzpB5NqHpZNkQ3NMDj13F" +
    "n8fzO0JB83Etbm_tnFQfcb13X3bJ15Cz-Ww1MGhvIpGGnMBT_ADp9xSIyAM9dQ1yeVXk-AIgWBUlN5uyWSGyCxp0cJwx7HxM38z0UIeBu-MytL-" +
    "eqndM7LxytsVzCbjOTSVRmhYEMIzUAnS1gs7uMQAGRdgRIElTJESGMjb_4bZq9s6Ve1LKkSi0_QDsrABaLe55UY0zF4ZSfOV5PMyPtocwV_dcNP" +
    "lxLgNAD1BFX_Z9kAdMZQW6fAmsfFle0zAoMe4l9pMESH0JB4sJGdCKtQXj1cXNydDYozF7l8H00BV_Er7zd6VtIw0MxwkFCTatsv_R-GsBCH218" +
    "RgVPsfYhwVuT8R4HarpzsDBufC4r8_c8fc9Z278sQ081jFjOja6L2x0N_ImzFNXU6xwO-Ska-QeuvYZ3X_L31ZOX4Llp-7QSfgDoHnOxFv1Xws-" +
    "D5mDHD3zxOup2b2TppdKTZb9eW2vxUVviM8OI9atBfPKMGAOv9omA-6vv5IxUH0-lWMiHLQ_g8vnswp-Jav0c4t6URVUzujNOoNd_CBGGVnHiJT" +
    "CHl88LQxsqLHHIu4Fz-U2SGnlxGTj0-ihit2ELGRv4vO8E1BosTmf0cx3qgG0Pq0eOLBDIHsrdZ_CCAiTc0HVkMbyq1M6qEhM-q5P6y1QCIrwg." +
    "0HFmhOzsQ98nNWJjIHkR7A"

  private val plaintextBytes = ByteVector(123, 34, 107, 116, 121, 34, 58, 34, 82, 83, 65, 34, 44, 34, 107, 105, 100, 34,
    58, 34, 106, 117, 108, 105, 101, 116, 64, 99, 97, 112, 117, 108, 101, 116, 46, 108, 105, 116, 34, 44, 34, 117, 115,
    101, 34, 58, 34, 101, 110, 99, 34, 44, 34, 110, 34, 58, 34, 116, 54, 81, 56, 80, 87, 83, 105, 49, 100, 107, 74, 106,
    57, 104, 84, 80, 56, 104, 78, 89, 70, 108, 118, 97, 100, 77, 55, 68, 102, 108, 87, 57, 109, 87, 101, 112, 79, 74,
    104, 74, 54, 54, 119, 55, 110, 121, 111, 75, 49, 103, 80, 78, 113, 70, 77, 83, 81, 82, 121, 79, 49, 50, 53, 71, 112,
    45, 84, 69, 107, 111, 100, 104, 87, 114, 48, 105, 117, 106, 106, 72, 86, 120, 55, 66, 99, 86, 48, 108, 108, 83, 52,
    119, 53, 65, 67, 71, 103, 80, 114, 99, 65, 100, 54, 90, 99, 83, 82, 48, 45, 73, 113, 111, 109, 45, 81, 70, 99, 78,
    80, 56, 83, 106, 103, 48, 56, 54, 77, 119, 111, 113, 81, 85, 95, 76, 89, 121, 119, 108, 65, 71, 90, 50, 49, 87, 83,
    100, 83, 95, 80, 69, 82, 121, 71, 70, 105, 78, 110, 106, 51, 81, 81, 108, 79, 56, 89, 110, 115, 53, 106, 67, 116,
    76, 67, 82, 119, 76, 72, 76, 48, 80, 98, 49, 102, 69, 118, 52, 53, 65, 117, 82, 73, 117, 85, 102, 86, 99, 80, 121,
    83, 66, 87, 89, 110, 68, 121, 71, 120, 118, 106, 89, 71, 68, 83, 77, 45, 65, 113, 87, 83, 57, 122, 73, 81, 50, 90,
    105, 108, 103, 84, 45, 71, 113, 85, 109, 105, 112, 103, 48, 88, 79, 67, 48, 67, 99, 50, 48, 114, 103, 76, 101, 50,
    121, 109, 76, 72, 106, 112, 72, 99, 105, 67, 75, 86, 65, 98, 89, 53, 45, 76, 51, 50, 45, 108, 83, 101, 90, 79, 45,
    79, 115, 54, 85, 49, 53, 95, 97, 88, 114, 107, 57, 71, 119, 56, 99, 80, 85, 97, 88, 49, 95, 73, 56, 115, 76, 71,
    117, 83, 105, 86, 100, 116, 51, 67, 95, 70, 110, 50, 80, 90, 51, 90, 56, 105, 55, 52, 52, 70, 80, 70, 71, 71, 99,
    71, 49, 113, 115, 50, 87, 122, 45, 81, 34, 44, 34, 101, 34, 58, 34, 65, 81, 65, 66, 34, 44, 34, 100, 34, 58, 34, 71,
    82, 116, 98, 73, 81, 109, 104, 79, 90, 116, 121, 115, 122, 102, 103, 75, 100, 103, 52, 117, 95, 78, 45, 82, 95, 109,
    90, 71, 85, 95, 57, 107, 55, 74, 81, 95, 106, 110, 49, 68, 110, 102, 84, 117, 77, 100, 83, 78, 112, 114, 84, 101,
    97, 83, 84, 121, 87, 102, 83, 78, 107, 117, 97, 65, 119, 110, 79, 69, 98, 73, 81, 86, 121, 49, 73, 81, 98, 87, 86,
    86, 50, 53, 78, 89, 51, 121, 98, 99, 95, 73, 104, 85, 74, 116, 102, 114, 105, 55, 98, 65, 88, 89, 69, 82, 101, 87,
    97, 67, 108, 51, 104, 100, 108, 80, 75, 88, 121, 57, 85, 118, 113, 80, 89, 71, 82, 48, 107, 73, 88, 84, 81, 82, 113,
    110, 115, 45, 100, 86, 74, 55, 106, 97, 104, 108, 73, 55, 76, 121, 99, 107, 114, 112, 84, 109, 114, 77, 56, 100, 87,
    66, 111, 52, 95, 80, 77, 97, 101, 110, 78, 110, 80, 105, 81, 103, 79, 48, 120, 110, 117, 84, 111, 120, 117, 116, 82,
    90, 74, 102, 74, 118, 71, 52, 79, 120, 52, 107, 97, 51, 71, 79, 82, 81, 100, 57, 67, 115, 67, 90, 50, 118, 115, 85,
    68, 109, 115, 88, 79, 102, 85, 69, 78, 79, 121, 77, 113, 65, 68, 67, 54, 112, 49, 77, 51, 104, 51, 51, 116, 115,
    117, 114, 89, 49, 53, 107, 57, 113, 77, 83, 112, 71, 57, 79, 88, 95, 73, 74, 65, 88, 109, 120, 122, 65, 104, 95,
    116, 87, 105, 90, 79, 119, 107, 50, 75, 52, 121, 120, 72, 57, 116, 83, 51, 76, 113, 49, 121, 88, 56, 67, 49, 69, 87,
    109, 101, 82, 68, 107, 75, 50, 97, 104, 101, 99, 71, 56, 53, 45, 111, 76, 75, 81, 116, 53, 86, 69, 112, 87, 72, 75,
    109, 106, 79, 105, 95, 103, 74, 83, 100, 83, 103, 113, 99, 78, 57, 54, 88, 53, 50, 101, 115, 65, 81, 34, 44, 34,
    112, 34, 58, 34, 50, 114, 110, 83, 79, 86, 52, 104, 75, 83, 78, 56, 115, 83, 52, 67, 103, 99, 81, 72, 70, 98, 115,
    48, 56, 88, 98, 111, 70, 68, 113, 75, 117, 109, 51, 115, 99, 52, 104, 51, 71, 82, 120, 114, 84, 109, 81, 100, 108,
    49, 90, 75, 57, 117, 119, 45, 80, 73, 72, 102, 81, 80, 48, 70, 107, 120, 88, 86, 114, 120, 45, 87, 69, 45, 90, 69,
    98, 114, 113, 105, 118, 72, 95, 50, 105, 67, 76, 85, 83, 55, 119, 65, 108, 54, 88, 118, 65, 82, 116, 49, 75, 107,
    73, 97, 85, 120, 80, 80, 83, 89, 66, 57, 121, 107, 51, 49, 115, 48, 81, 56, 85, 75, 57, 54, 69, 51, 95, 79, 114, 65,
    68, 65, 89, 116, 65, 74, 115, 45, 77, 51, 74, 120, 67, 76, 102, 78, 103, 113, 104, 53, 54, 72, 68, 110, 69, 84, 84,
    81, 104, 72, 51, 114, 67, 84, 53, 84, 51, 121, 74, 119, 115, 34, 44, 34, 113, 34, 58, 34, 49, 117, 95, 82, 105, 70, 
    68, 80, 55, 76, 66, 89, 104, 51, 78, 52, 71, 88, 76, 84, 57, 79, 112, 83, 75, 89, 80, 48, 117, 81, 90, 121, 105, 97,
    90, 119, 66, 116, 79, 67, 66, 78, 74, 103, 81, 120, 97, 106, 49, 48, 82, 87, 106, 115, 90, 117, 48, 99, 54, 73, 101,
    100, 105, 115, 52, 83, 55, 66, 95, 99, 111, 83, 75, 66, 48, 75, 106, 57, 80, 97, 80, 97, 66, 122, 103, 45, 73, 121,
    83, 82, 118, 118, 99, 81, 117, 80, 97, 109, 81, 117, 54, 54, 114, 105, 77, 104, 106, 86, 116, 71, 54, 84, 108, 86,
    56, 67, 76, 67, 89, 75, 114, 89, 108, 53, 50, 122, 105, 113, 75, 48, 69, 95, 121, 109, 50, 81, 110, 107, 119, 115,
    85, 88, 55, 101, 89, 84, 66, 55, 76, 98, 65, 72, 82, 75, 57, 71, 113, 111, 99, 68, 69, 53, 66, 48, 102, 56, 48, 56,
    73, 52, 115, 34, 44, 34, 100, 112, 34, 58, 34, 75, 107, 77, 84, 87, 113, 66, 85, 101, 102, 86, 119, 90, 50, 95, 68,
    98, 106, 49, 112, 80, 81, 113, 121, 72, 83, 72, 106, 106, 57, 48, 76, 53, 120, 95, 77, 79, 122, 113, 89, 65, 74, 77,
    99, 76, 77, 90, 116, 98, 85, 116, 119, 75, 113, 118, 86, 68, 113, 51, 116, 98, 69, 111, 51, 90, 73, 99, 111, 104,
    98, 68, 116, 116, 54, 83, 98, 102, 109, 87, 122, 103, 103, 97, 98, 112, 81, 120, 78, 120, 117, 66, 112, 111, 79, 79,
    102, 95, 97, 95, 72, 103, 77, 88, 75, 95, 108, 104, 113, 105, 103, 73, 52, 121, 95, 107, 113, 83, 49, 119, 89, 53,
    50, 73, 119, 106, 85, 110, 53, 114, 103, 82, 114, 74, 45, 121, 89, 111, 49, 104, 52, 49, 75, 82, 45, 118, 122, 50,
    112, 89, 104, 69, 65, 101, 89, 114, 104, 116, 116, 87, 116, 120, 86, 113, 76, 67, 82, 86, 105, 68, 54, 99, 34, 44,
    34, 100, 113, 34, 58, 34, 65, 118, 102, 83, 48, 45, 103, 82, 120, 118, 110, 48, 98, 119, 74, 111, 77, 83, 110, 70,
    120, 89, 99, 75, 49, 87, 110, 117, 69, 106, 81, 70, 108, 117, 77, 71, 102, 119, 71, 105, 116, 81, 66, 87, 116, 102,
    90, 49, 69, 114, 55, 116, 49, 120, 68, 107, 98, 78, 57, 71, 81, 84, 66, 57, 121, 113, 112, 68, 111, 89, 97, 78, 48,
    54, 72, 55, 67, 70, 116, 114, 107, 120, 104, 74, 73, 66, 81, 97, 106, 54, 110, 107, 70, 53, 75, 75, 83, 51, 84, 81,
    116, 81, 53, 113, 67, 122, 107, 79, 107, 109, 120, 73, 101, 51, 75, 82, 98, 66, 121, 109, 88, 120, 107, 98, 53, 113,
    119, 85, 112, 88, 53, 69, 76, 68, 53, 120, 70, 99, 54, 70, 101, 105, 97, 102, 87, 89, 89, 54, 51, 84, 109, 109, 69,
    65, 117, 95, 108, 82, 70, 67, 79, 74, 51, 120, 68, 101, 97, 45, 111, 116, 115, 34, 44, 34, 113, 105, 34, 58, 34,
    108, 83, 81, 105, 45, 119, 57, 67, 112, 121, 85, 82, 101, 77, 69, 114, 80, 49, 82, 115, 66, 76, 107, 55, 119, 78,
    116, 79, 118, 115, 53, 69, 81, 112, 80, 113, 109, 117, 77, 118, 113, 87, 53, 55, 78, 66, 85, 99, 122, 83, 99, 69,
    111, 80, 119, 109, 85, 113, 113, 97, 98, 117, 57, 86, 48, 45, 80, 121, 52, 100, 81, 53, 55, 95, 98, 97, 112, 111,
    75, 82, 117, 49, 82, 57, 48, 98, 118, 117, 70, 110, 85, 54, 51, 83, 72, 87, 69, 70, 103, 108, 90, 81, 118, 74, 68,
    77, 101, 65, 118, 109, 106, 52, 115, 109, 45, 70, 112, 48, 111, 89, 117, 95, 110, 101, 111, 116, 103, 81, 48, 104,
    122, 98, 73, 53, 103, 114, 121, 55, 97, 106, 100, 89, 121, 57, 45, 50, 108, 78, 120, 95, 55, 54, 97, 66, 90, 111,
    79, 85, 117, 57, 72, 67, 74, 45, 85, 115, 102, 83, 79, 73, 56, 34, 125)


  "PBES2" should "succeed with decrypt" in {
    val run =
      for
        keyBytes <- toBytes(password).eLiftET[IO]
        key = PBKDF2.secretKeySpec(keyBytes)
        jwe <- JsonWebEncryption.parse(cs).asError.eLiftET[IO]
        header <- jwe.getUnprotectedHeader.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](key))
        payload <- decrypted.decodeUtf8.asError.eLiftET
        jwk <- decode[Id, JsonWebKey](payload).eLiftET[IO]
      yield
        jwk.keyID.contains(KeyId("juliet@capulet.lit")) && jwk.keyType == KeyType.RSA &&
          jwk.publicKeyUse.contains(PublicKeyUseType.Encryption)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PBES2" should "succeed with encrypt" in {
    val encodedHeader = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk" +
      "2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ"
    val expectedDerived = ByteVector(110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75)
    val exampleCek = ByteVector(111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55,
      202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182)
    val expectedEncryptedKey = ByteVector(78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66,
      125, 36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33, 245, 57, 59, 4)
    val encodedIv = "Ye9j1qs22DmRSAddIh-VnA"
    val run =
      for
        headerBase <- Base64UrlNoPad.fromString(encodedHeader).eLiftET[IO]
        header <- fromBase[JoseHeader](headerBase).eLiftET[IO]
        keyBytes <- toBytes(password).eLiftET[IO]
        key = PBKDF2.secretKeySpec(keyBytes)
        pbes2SaltInput <- decodeOption(header.pbes2SaltInput).eLiftET[IO]
        (derivedKey, saltInput, iterationCount) <- `PBES2-HS256+A128KW`.deriveForEncrypt[IO](key, pbes2SaltInput,
          header.pbes2Count, None, None)
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, _, _, _, _, _) <- EitherT(`PBES2-HS256+A128KW`
          .encryption.encryptKey[IO](derivedKey, exampleCek.length.toInt, AES, Some(exampleCek)))
        aad <- ByteVector.encodeAscii(encodedHeader).asError.eLiftET[IO]
        ivBase <- Base64UrlNoPad.fromString(encodedIv).eLiftET[IO]
        iv <- ivBase.decode[Id].eLiftET[IO]
        ContentEncryptionParts(_, ciphertext, authenticationTag) <- EitherT(`A128CBC-HS256`.encrypt[IO](
          contentEncryptionKey, plaintextBytes, aad, Some(iv)).asError)
        jweCompact <- JsonWebEncryption(headerBase, None, None, Base64UrlNoPad.fromByteVector(encryptedKey), ivBase,
          Base64UrlNoPad.fromByteVector(ciphertext), Base64UrlNoPad.fromByteVector(authenticationTag), None)
          .compact.eLiftET
      yield
        ByteVector(derivedKey.getEncoded) === expectedDerived && contentEncryptionKey === exampleCek &&
          encryptedKey === expectedEncryptedKey && jweCompact == cs
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PBES2" should "succeed with round trips" in {
    val tests =
      for
        alg <- PBES2Algorithm.values
        enc <- AESCBCHmacSHA2Algorithm.values
      yield
        pbes2RoundTrip(alg, enc)
    tests.sequence.value.map(_.map(_.forall(identity)).getOrElse(false)).asserting(assert)
  }

  private def pbes2RoundTrip(alg: PBES2Algorithm, enc: AESCBCHmacSHA2Algorithm): EitherT[IO, Error, Boolean] =
    val password = "password"
    val plaintext = "<insert some witty quote or remark here>"
    for
      keyBytes <- toBytes(password).eLiftET[IO]
      key = PBKDF2.secretKeySpec(keyBytes)
      plaintextBytes <- toBytes(plaintext).eLiftET[IO]
      jwe <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(alg), Some(enc))))
      jweCompact <- jwe.compact.eLiftET[IO]
      jwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
      decrypted <- EitherT(jwe.decrypt[IO](key))
      decryptedPlaintext <- decrypted.decodeUtf8.asError.eLiftET[IO]
    yield
      decryptedPlaintext == plaintext

  "PBES2" should "succeed with defaults meet minimum required or suggested" in {
    val run =
      for
        keyBytes <- toBytes("passtheword").eLiftET[IO]
        key = PBKDF2.secretKeySpec(keyBytes)
        plaintextBytes <- toBytes("meh").eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(`PBES2-HS256+A128KW`),
          Some(`A128CBC-HS256`))))
        jweCompact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](key))
        _ <- decrypted.decodeUtf8.asError.eLiftET
        header <- jwe.getUnprotectedHeader.eLiftET[IO]
        pbes2SaltInput <- decodeOption(header.pbes2SaltInput).eLiftET[IO]
      yield
        header.pbes2Count.exists(_ >= minimumIterationCount) && pbes2SaltInput.exists(_.length >= minimumSaltByteLength)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PBES2" should "succeed with setting salt and iteration count" in {
    val password = "secret word"
    val plaintext = "<insert some witty quote or remark here, again>"
    val saltByteLength = 32
    val iterationCount = 1024L
    val run =
      for
        keyBytes <- toBytes(password).eLiftET[IO]
        key = PBKDF2.secretKeySpec(keyBytes)
        plaintextBytes <- toBytes(plaintext).eLiftET[IO]
        pbes2SaltInput <- EitherT(randomBytes[IO](saltByteLength).asError)
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(`PBES2-HS384+A192KW`),
          Some(`A192CBC-HS384`), pbes2SaltInput = Some(Base64UrlNoPad.fromByteVector(pbes2SaltInput)),
          pbes2Count = Some(iterationCount))))
        jweCompact <- jwe.compact.eLiftET[IO]
        jwe <- JsonWebEncryption.parse(jweCompact).asError.eLiftET[IO]
        decrypted <- EitherT(jwe.decrypt[IO](key))
        decryptedPlaintext <- decrypted.decodeUtf8.asError.eLiftET
        header <- jwe.getUnprotectedHeader.eLiftET[IO]
        decodedPbes2SaltInput <- decodeOption(header.pbes2SaltInput).eLiftET[IO]
      yield
        decryptedPlaintext == plaintext && header.pbes2Count.contains(iterationCount) &&
          decodedPbes2SaltInput.exists(saltInput => saltInput === pbes2SaltInput && saltInput.length == saltByteLength)
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PBES2" should "failed with too small iteration count rejected" in {
    val password = "super secret word"
    val plaintext = "some text"
    val iterationCount = 918L
    val run =
      for
        keyBytes <- toBytes(password).eLiftET[IO]
        key = PBKDF2.secretKeySpec(keyBytes)
        plaintextBytes <- toBytes(plaintext).eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(`PBES2-HS256+A128KW`),
          Some(`A128CBC-HS256`), pbes2Count = Some(iterationCount))))
      yield
        jwe
    run.value.map {
      case Left(error) => true
      case _ => false
    }.asserting(assert)
  }

  "PBES2" should "failed with too little salt rejected" in {
    val password = "super secret word"
    val plaintext = "some text"
    val run =
      for
        keyBytes <- toBytes(password).eLiftET[IO]
        key = PBKDF2.secretKeySpec(keyBytes)
        plaintextBytes <- toBytes(plaintext).eLiftET[IO]
        pbes2SaltInput <- Base64UrlNoPad.fromString("bWVo").eLiftET[IO]
        jwe <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(`PBES2-HS256+A128KW`),
          Some(`A128CBC-HS256`), pbes2SaltInput = Some(pbes2SaltInput))))
      yield
        jwe
    run.value.map {
      case Left(error) => true
      case _ => false
    }.asserting(assert)
  }
end PBES2AlgorithmFlatSpec
