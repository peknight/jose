package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.encryption.*
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import java.security.interfaces.{ECPrivateKey, RSAPrivateKey}

class JsonWebKeySetFilterFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKeySetFilter" should "succeed with some X5 selections" in {
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"v5UvsMi60ASbQEIKdOdkXDfBRKgoLHH4lZLwUiiDq_VscTatbZDvTFnfmFKHExTz" +
      "n0LKTjTNhKhY81CNLTNItRqmsTZ5cMnR0PTS777ncQ70l_YxAXxpBWANOkEPzRMbF4R7d9GBJQUzKgVVWvGH_6BG-oSuDMc82j3rInMp38T-a" +
      "fcf3F9gcpfhELM1xChfjaMyExLezhPi2F4O41z9kWpHF3hYwu-h_xuJA_apc2gPf1RvpB6v2m4ll4QdnQIu1MIb_8z7018OWdCIUf2sGVepnH" +
      "osiNxfdhmu9brwXSbYcbWVJUdmhB5bZze3af5nI4qtX_BV_YPgsfsczAKmuQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIDKDCCAhCgAwIBAgIG" +
      "AUqtA+agMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlN" +
      "GoxFzAVBgNVBAMTDkJyaWFuIENhbXBiZWxsMB4XDTE1MDEwMjIzMzg0MVoXDTQyMDgyNDIyMzg0MVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBA" +
      "gTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQU" +
      "AA4IBDwAwggEKAoIBAQC\\/lS+wyLrQBJtAQgp052RcN8FEqCgscfiVkvBSKIOr9WxxNq1tkO9MWd+YUocTFPOfQspONM2EqFjzUI0tM0i1Gq" +
      "axNnlwydHQ9NLvvudxDvSX9jEBfGkFYA06QQ\\/NExsXhHt30YElBTMqBVVa8Yf\\/oEb6hK4MxzzaPesicynfxP5p9x\\/cX2Byl+EQszXEK" +
      "F+NozITEt7OE+LYXg7jXP2RakcXeFjC76H\\/G4kD9qlzaA9\\/VG+kHq\\/abiWXhB2dAi7Uwhv\\/zPvTXw5Z0IhR\\/awZV6mceiyI3F92" +
      "Ga71uvBdJthxtZUlR2aEHltnN7dp\\/mcjiq1f8FX9g+Cx+xzMAqa5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABwJ7Iw904nf4KiTviWa3j3" +
      "OWauSOV0GpM\\/ORJbsIvqUada5VubOrN0+NRQJm3\\/TTFOIsvRqL86cpFf7ikpdfLjyKR\\/ZQVrop9yoCPQAiLe7IcPozngaLoHOK2OcEW" +
      "RDbxPfBnhmxfyGqMxtXuqVIEIQ40AIjdimHgbTbmaMQIZpANgHryfJDrQJX2UXnqgtCYaJzoLJMFY7BrlO8mCSez8V886DpbTzXYJwDk4GCDY" +
      "UTEvNUbFVvpVoWaYX2JtwP1fm+lQtiKhHyp1PCJh\\/5Ijbf6sTlONXWVSreWw6LKjixM\\/HNJnK5Yd3vSql\\/nwI3Cy2kGgzjCzUfcyQ\\" +
      "/LU+2tI=\"],\"d\":\"Df2lF_HwwpQzikPIY7UqPRnNQWhOVsCT-MhcSIOw6fPoUXQ-wgudjiPaElOkjZ4wFGdaQs_UWmW46Tvus2hVXPRvS" +
      "-3AfJ4gdnQKm3uDh1wiPJ68AXHGcaAMFz79GmrUxajlI2DnX367t8vf6d5NojtgM5dQ5pn-Nanj7AYg_rhRjGjK783PepBCAHQ2zwdGBHaS_1" +
      "e4IErtyCFiJN405O6_jacmdIEPATSNNItnrGVTDQjCI0hswVqXeOr2pUEDLWuXEcKS-0xZ4T1MV1MDipoNy4EtxHrQrXd32aY7IIp3QMWAgxe" +
      "ES24dSZRhdFICFPEhNb_jq88bpaGR6sbLAQ\",\"p\":\"-oaNOH47V97ZhC-YkPIpmVXVWVLmna1_dy_eBGpMqgITVyYJIBEY7S6BSEhm9bT" +
      "LayCL_tePv3bgzzzusE2sAVcc-0ifoE2tFMi3gpk9130xEjQwDmFXcddCfjKbqf4nJWrmfTqAGIOu2A4JGozqcLRJdxbtDpP9X8Nk5vN52jE" +
      "\",\"q\":\"w8ToEQ64_Hfxd-gnMyR4rI6jnnOlD884M3APYK8tHcux19n37zgEF29h9cn4h5Kyfs0x90ThGLtPPthCphqdS6K5v50X7A6p43" +
      "GwojK9Ut2JT8FZxo6dlBBxtElE481sL832f_nBBpik9stz_JJvg89BvSNnjIldBmbfaG2f6wk\",\"dp\":\"N-7iiMJmLXAr0D9wKKxobTuk" +
      "rpS7uGiMFOgzAXlaNHrSJprvXqFyl0HSy3iexCzhXcGef_9QsMax2pMYF3S_-mygo9nLCddN1V4a2qWsEPh6hD3ynMNO6rPMvLA_4OxFgS0k2" +
      "MC-6Lo9xy8bCTp8_TzDSjtsId0YrNDLLmUdx4E\",\"dq\":\"Vyc6CR38zKi5HyCDEwmRj4CQ5uGlAjzGUF_6-JgEBdfA_M9UyXKun6A-hCW" +
      "-NtzgCgNf0y0e6Nu6k8fDJB-FFz8CYoOVOsnsaA0dDZh5IILvtknlpben_1qyxAg6WxAAseeHbcHKZR1fk19P64lli9Cg-4rfdnlQqKDzpJHp" +
      "N8E\",\"qi\":\"8OHKueEcRf0KpoWmowEI4IFZRTZoSxDNxFlA5J0E5nMtqKxOLVVKn_wOQsUK1u4UOn4ull7ZbbRMZRhOLnVyggpHgJ7BN9" +
      "hmiYUgN7qJx9PxSz0AZTUpX-FIP5V4p30tspPvfCHsbvZ2Sq-sB6BaPzV33W1X-Uc2kfl4EOsV-nA\"},{\"kty\":\"RSA\",\"n\":\"nea" +
      "Z2O9Auht0ZASyP4wr_kTkIis1QQkFXTD-gW9sXJQhYb6sISSGt_uu5lPZTcbLfIyROLgjWLcG7lPQ6dxbKtcU51wiFWLYu4Qjvk7zD17YJQD8" +
      "xH0j5dzyo7zJqLbJjY3a32_V9K6r3O-MpGObH7BFs_PokvQkNHYIgwQR2KJfH_LDihRBcNV4pjrRa2qyeEjH5-wd21AqJdPgKnW-o92xGU-G7" +
      "1Qk6qOdjMDYnlXMEwvtxBssi22cgAlSAcW0p4pFUQWQUxahAND_LdACc-iGxLMxtvddJ9pxQxgBW8qQJratiwjCpYBVCB6Gw9uA76Ee65lF3f" +
      "p8ldUt32mzCw\",\"e\":\"AQAB\",\"x5c\":[\"MIIDNDCCAhygAwIBAgIGAUqtD7sRMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAlVT" +
      "MQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxHTAbBgNVBAMTFEJyaWFuIERhdmlkIENhbXBiZWxsMB4XD" +
      "TE1MDEwMjIzNTEzNloXDTQ1MDUyMDIyNTEzNlowWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBA" +
      "oTBmpvc2U0ajEdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCd5pnY70C6G3R" +
      "kBLI\\/jCv+ROQiKzVBCQVdMP6Bb2xclCFhvqwhJIa3+67mU9lNxst8jJE4uCNYtwbuU9Dp3Fsq1xTnXCIVYti7hCO+TvMPXtglAPzEfSPl3P" +
      "KjvMmotsmNjdrfb9X0rqvc74ykY5sfsEWz8+iS9CQ0dgiDBBHYol8f8sOKFEFw1XimOtFrarJ4SMfn7B3bUCol0+Aqdb6j3bEZT4bvVCTqo52" +
      "MwNieVcwTC+3EGyyLbZyACVIBxbSnikVRBZBTFqEA0P8t0AJz6IbEszG2910n2nFDGAFbypAmtq2LCMKlgFUIHobD24DvoR7rmUXd+nyV1S3f" +
      "abMLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI94fDaieGwkj1dDSEM+2TJwrciMGdUM8EgMeWsVQgTS+xfkmvP5fjYW78eQ8072lYfkodsyC" +
      "00hsUl8LFzsVKbAgU\\/+GQCVwd++JdguC8g3186cp2l6WxPHYFkCJs3QGEnarMIeD42dBjIB2HueOJ5rDKz6sC2g2c2lC7rTs662HPztPY9d" +
      "RYLxWmy47C4YdPcn8toNatQjkC3j+w3K5QWZe5tf1X6C0xClmss8WyI+qJV13aPjHu8ybYJec5jryzKr9qT\\/t2YOzrvszkNTrUNFz4JCD9L" +
      "XM0Vl5gdp6QOBSzwzhMeZcGJCQRuJa8fo\\/sCsoZFNzuNtmc5N2b5jxXQ=\"],\"d\":\"lOH0OioNW-27JvuOnoCqkouel-Epy3KYDjC-KI" +
      "lJIVnCyAki__US2bOETETPZpiFEaDw5Qwqt-GLtXhuSbOueoxmd2fV81hKhzSnBzAl2l5Ra0KtEw_zoy9b0auWcXA4RzJ0J62pjZaNEjsE35P" +
      "TlmN8tZrLtpRg9t48VFyn_xxLMNth3SDn36jVpeCI5KZEitwaVzi5nnYONfpLT9v_iD8GRu1zUKeuXMbMbEcQW8WaoPQmPgrqaf7YD8apfS_6" +
      "o5VQhl4SnY6mDnd1DnU3XnVS3JgNV5CKUZek1Tb27b6Z1YVpowgWcBQqXZz21pNVgDUrh8opLGZ1aFFgTBz38Q\"},{\"kty\":\"RSA\",\"" +
      "n\":\"7LnNihjvihRLAHlwPC4rTAI-ToPNspm-QV9UTrNSYTdL_DePpuvWqis8iqOnWNzjTTQgBj__D6fjz7gdKnsdUtHT0H70inY92kU96MJ" +
      "aiIQol9ZxrGfjIumejOcbEkAmmfrMKPASl4US_NpcPYMtFzjJ3txNm6cgAVzYdZEmtW1vVa86etICUDQ_eD3bpHY4vcWB7m8slnnZ4JFbojDs" +
      "fJUhTEuHzr_rkXI6XVrdv8kPnbEBK7dfbZVlcguQ1nFCiIUY4MO8f-zF7rF3d3AvqtxmQqNT_L1a67O0aoPldNmFJ0nl2hKywKwhx52fMT8VU" +
      "qAT_W-aY-Ody-H8GWZBqw\",\"e\":\"AQAB\",\"x5c\":[\"MIIDLjCCAhagAwIBAgIGAUqtEXLzMA0GCSqGSIb3DQEBCwUAMFgxCzAJBgN" +
      "VBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxGjAYBgNVBAMTEUJyaWFuIEQuIENhbXBiZWxs" +
      "MB4XDTE1MDEwMjIzNTMyOVoXDTQzMDYyMDIyNTMyOVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANB" +
      "gNVBAoTBmpvc2U0ajEaMBgGA1UEAxMRQnJpYW4gRC4gQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsuc2KGO+KFE" +
      "sAeXA8LitMAj5Og82ymb5BX1ROs1JhN0v8N4+m69aqKzyKo6dY3ONNNCAGP\\/8Pp+PPuB0qex1S0dPQfvSKdj3aRT3owlqIhCiX1nGsZ+Mi6" +
      "Z6M5xsSQCaZ+swo8BKXhRL82lw9gy0XOMne3E2bpyABXNh1kSa1bW9Vrzp60gJQND94Pdukdji9xYHubyyWedngkVuiMOx8lSFMS4fOv+uRcj" +
      "pdWt2\\/yQ+dsQErt19tlWVyC5DWcUKIhRjgw7x\\/7MXusXd3cC+q3GZCo1P8vVrrs7Rqg+V02YUnSeXaErLArCHHnZ8xPxVSoBP9b5pj453" +
      "L4fwZZkGrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEL302pFrgsVDleaME1BvtTmZvE9ffBpiOc8k6kUpg30\\/I\\/ptXVHbMXcCLckn8OE" +
      "clp8yf\\/8KgD0tZ5Sb501ucfYKWOKR1WBR1QunnLgzKiNflnZzITrXWI+cfwiJwn\\/PE2M5975dTDGeyzpGB6Tfn7HrfdLfoyMk5+rwehfG" +
      "5\\/vX82fCZLM6NbxViaXJSud9hCVbxJEvvTUlVmVOrWhuebBJbtut4+RfI0RMm3AwYmRqZmnmNV85HZ9J5li7CoPHE9UHxxR8R8GWnsjQuB5" +
      "og50FpGTub7OkyFTCnYSAUxmZYk4Z1BN8zMOD+JKOa5kZINouifPiwtXjq4aL7YCBUc=\"],\"d\":\"R8h75FF1abiHmcg5WXZimLThceuT1" +
      "4G5aJdguFC2PVaISx4KCILhYE6mGCBSIacxofqZb2u-i1_Mu_NHnNciaDfKdCHbQ5VhYiu2_zrYOydgK9LSO4ZxIOgYtP9rfRhI3E5p1EwgRy" +
      "QKQvRwHhMF_FGzHUpOmlGOaftehCAUzdShLfZdNp93ohpqamal1uisx9dbGqI1vX5_mQpvoH2OGBIhlVbp5EKMqib724y3GLOrbYgJDM_Z1BR" +
      "NNSy51oceXieV7GcX-oT2Xv3YZfsLyM8JSZJzIiSl6_bykvGSxRv3E25JrtHtX9GDpE0YdatXm030_o2TjWtIfBZPabE5mQ\",\"p\":\"964" +
      "kN9rx7_aWNj3vYHEkD4f_ka-JRDQknBgIdkK6use7oe6WE0iyhJolNemJRwB_JpAQ9kBfYjoyqgv_22tTvDAqU75uTm8mhvsefPxur-khp4Iu" +
      "UfwhbvT7GfR45-fbpubf8ic0IZ-PM6tc3mAYV4KEOGk4proUTO1FHYK8Yx8\",\"q\":\"9K12LZkuTK80EE1e7Z9QuOMR_kl4UUWDaJUmGMx" +
      "I6Dh5EZ60Ny2jja3-vAzBxknfxopQpQa4A77ePTCChHBEw5uCC7AZAmeIuU2qqb1XZd2_7CBkJjsyxEr09eXDzy4sEqME9Ql6kCC6XZQ2Likm" +
      "QuLvS7VddEMrdez90wiU-_U\",\"dp\":\"NJWaRumLGCFIPvfjTJx4xXtgPTQBdqODakiH82OzdVhWc8jNwAZdMF3xrIKKjLKETFGl6EI-fg" +
      "JRI10s0w70Vi37ro_tp2VdzqaeEHcfoOVkKcYvw2Q-TOpiLV6EFOha8BJwVV8RaFoR8yxcqTHJuTqSi897IZq8GKD_XYaWLI0\",\"dq\":\"" +
      "LOygczTZ5zGiS1Z9vG5AR4TCIADl7JujtfMlNymXPyRt9VzfdfPgbPItC50IsXfz4YlrI_dPi-4UTBwceH7UBWyz1TrIRlXhvCR7yg-Ho5yI0" +
      "9-TmnoJmCtZ8bZ23OxYOL4nRAjCwWUA5F6971zPk-4jxSORO-WbP1wIhhJrhx_U\",\"qi\":\"F7hzNEUauVSoyi9xSmp7uHSIHE3BiPMq-_" +
      "_Z1fZ7oODk3kmJeFzw3Jx5g8NaHsixA7DPb-aQ2Y_XPZPL28EuJqz2bbGguK9pAvwhqAPTZoNjWpJe5Ds5hL5dvGIxvvSLlZdgQmxzfsU_e1L" +
      "tE5vae1kd5RxZgjcZ5Ssn9rBJBlQ\"},{\"kty\":\"EC\",\"x\":\"bhH1zISTvaqIluqvQHcVXNVkf-oJlo3MXI34TvPpn0Y\",\"y\":" +
      "\"a2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQ\",\"crv\":\"P-256\",\"x5c\":[\"MIIBoDCCAUSgAwIBAgIGAUqv7HETMAwG" +
      "CCqGSM49BAMCBQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEA" +
      "xMOQnJpYW4gQ2FtcGJlbGwwHhcNMTUwMTAzMTMxMTU1WhcNNDMwNjIxMTIxMTU1WjBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBg" +
      "NVBAcTBkRlbnZlcjEPMA0GA1UEChMGam9zZTRqMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG4" +
      "R9cyEk72qiJbqr0B3FVzVZH\\/qCZaNzFyN+E7z6Z9Ga2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQwDAYIKoZIzj0EAwIFAANIAD" +
      "BFAiEA7s85afZ5+ROkthajh87xg89spz8lzDmGolzPfbuPULwCICZC1q3Xyk70KKpZWpXaSlu0bfMkuNwG7RtMPv+ao+zb\"],\"d\":\"81b" +
      "MjwCNiMA8ZVRGSXkf9nSGvZ-uWTcFTZCu3S8TvAw\"},{\"kty\":\"EC\",\"x\":\"3CpPM7n0EwqENMDNKuDMkx5nNZ7F9xQKJ1FJ7XQY7" +
      "Os\",\"y\":\"_B-nBJwT7Qsdv3RpAIZY-1NaZgzE-Mdu_CsWJ7LBDxk\",\"crv\":\"P-256\",\"x5c\":[\"MIIBqjCCAVCgAwIBAgIGA" +
      "Uqv7n85MAwGCCqGSM49BAMCBQAwWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0aj" +
      "EdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJlbGwwHhcNMTUwMTAzMTMxNDEwWhcNNDgwMjEyMTMxNDEwWjBbMQswCQYDVQQGEwJVUzELMAk" +
      "GA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEPMA0GA1UEChMGam9zZTRqMR0wGwYDVQQDExRCcmlhbiBEYXZpZCBDYW1wYmVsbDBZMBMGByqG" +
      "SM49AgEGCCqGSM49AwEHA0IABNwqTzO59BMKhDTAzSrgzJMeZzWexfcUCidRSe10GOzr\\/B+nBJwT7Qsdv3RpAIZY+1NaZgzE+Mdu\\/CsWJ" +
      "7LBDxkwDAYIKoZIzj0EAwIFAANGADBDAh8N9cKJYRq8kMmbpoqaB6PT\\/uVPK++RxBy5SWqCl0y1AiAQJfMfQJxZBZ0iCNYcpFmTpXIPaVxu" +
      "50XHqafQETYQBg==\"],\"d\":\"LzVM5880beqKgVOnrab4PCNiIEpaUa8niRaOsZY0apc\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        x509CertificateSHA1Thumbprint1 <- Base64UrlNoPad.fromString("Zb1HT7ryCRAAj2wcQ8hWbzaqX1s").eLiftET[IO]
        keys1 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(`RSA-OAEP`),
          x509CertificateSHA1Thumbprint = Some(x509CertificateSHA1Thumbprint1)), None, None, empty, empty, empty, empty,
          None)))
        x509CertificateSHA1Thumbprint2 <- Base64UrlNoPad.fromString("W8aO-BD2jx9KMzQjhZ85ukJA5Zg").eLiftET[IO]
        keys2 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES`),
          x509CertificateSHA1Thumbprint = Some(x509CertificateSHA1Thumbprint2)), None, None, empty, empty, empty, empty,
          None)))
        x509CertificateSHA256Thumbprint <- Base64UrlNoPad.fromString("CJy-lAE3X0ar44cKrxKcauUHApD_ktFjPC9s6HeOxzU")
          .eLiftET[IO]
        keys3 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(RSA1_5),
          x509CertificateSHA256Thumbprint = Some(x509CertificateSHA256Thumbprint)), None, None, empty, empty, empty,
          empty, None)))
      yield
        keys1.length == 1 && keys1.head.key.isInstanceOf[RSAPrivateKey] &&
          keys2.length == 1 && keys2.head.key.isInstanceOf[ECPrivateKey] &&
          keys3.length == 1 && keys3.head.key.isInstanceOf[RSAPrivateKey]
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetFilter" should "succeed with some kid selections" in {
    val json = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"rSK-0_k\",\"use\":\"enc\",\"x\":\"qQGegqPCpvi9tLJF_ofPR6PJIRb-O" +
      "gZX3n8TKwR5a30\",\"y\":\"HQAAFdTf3O1egAoYGmsPDjaIYdeS6Gm-Dv175yim4OM\",\"crv\":\"P-256\",\"d\":\"aI6PD_LfL4lF" +
      "UdyAHFnRSUYhBL_8k7gxfoDXeWiI1Gs\"},{\"kty\":\"EC\",\"kid\":\"KGAbCMI\",\"use\":\"enc\",\"x\":\"nfXylbOqF7aW5w" +
      "nMzc5mWuSgx5Kfkx8wXw62ZTxVhmQRP_2XfV5hE_ek-AxOI4UG\",\"y\":\"s-cIx-W0y7Aep7dxiArL_n3HSBODcvUyNBc510OiAOFkV6J_" +
      "wNcb5QokT9LsKRYi\",\"crv\":\"P-384\",\"d\":\"iSs9l_3Tlyeco1LzblzPoOdcvLYZum4hY75M9b0fCrULhqSIeyXu53THp-wZ_Hdt" +
      "\"},{\"kty\":\"EC\",\"kid\":\"4AFzkhA\",\"use\":\"enc\",\"x\":\"AcZBC-sgcJpUjP3P6wUNYW1nBH8AduQi_vjjOgaFg-35_" +
      "ZYDUckp0yw4BnpKEQvueYmbNoEVpf4dWslLhiWtxHRR\",\"y\":\"AJcl35TUpqKJTmrRDW3MiC5gxuAteeBwHofnTXA5JhSbUKxEAx0hMuR" +
      "cRgMHV47MqwxriEReR06Vhk152eh4tTOL\",\"crv\":\"P-521\",\"d\":\"AdJ-14bVfrfErJjkfPuwTzbeLeZN9Doqb6mOPwSZYDReMoG" +
      "gXa0d44X4d53lYAC1nQHLyLjXt3A8KIjXWwwdnSsi\"},{\"kty\":\"RSA\",\"kid\":\"Lu8lh94\",\"use\":\"enc\",\"n\":\"rgS" +
      "8RROXfdBwXMfU9NMMw-m-HfWRDSZU6Vmhbqrd4jOGwHlbKNcEy7U5-FaTBp1JLXOdR4sYmY2TdU36GapWYPQtVqqUUhPxudBlmP9JkMG9XC25" +
      "N-O0-hIp2F40tMGHTcdOo8nb6UgPFV96XJsCUrODdtXDKBt7o50ahLjql_iXP0QxlX-kPcd-ANKIRVBJa7VPKf9xH1iF6bvAio8SgHB2QXanc" +
      "d9CmobisPhqbck6Szv5SxhPTQ3ZV5aRP8UB9fCBvbD8POQY-YqF1xNo7qwosX2PC-Q0ejn4Saf3jwE79stybi-JIytRs93YUh3w3LLzGqprMH" +
      "dUqNc01-h1Ew\",\"e\":\"AQAB\",\"d\":\"NFiUUasdDOmggyhRdPvvgRdU6yotYek_7Znap7GaYSrixA89TsGvXZ-8OmnAfGLf2l5G13i" +
      "OA9LEoqq8KvBEX5HT-ZgCWdZKBn0bsrRIatT8ozfV2WwTyo2gLMfZzu3QR6NGkppsHnZgoys_YY_3WO1LBHo05GGwBX2Ctp3xY5kS2rgUlbnW" +
      "x2FbNsnokR6dD1PordCMNiSgg_r3l3dB4FbDI_7Xi8n4XH9vIf6wd60FRhtNChS1Ybrny0GadHUvUKshnnwaCfda2u3iY4qI8mRiH6a9zg294" +
      "3peLxNlSegZ9ceCQAGAXPhC77B3Nth4K4JDsHLD6ItrLFIOt6A2gQ\",\"p\":\"0xnpS1_Dj5A4QCRgFPEryaA-kQmes6fpSaP9ETncvTQ4L" +
      "duSdMsLua5-6FF_FV50cgtOUvYh7DiR93Xq_GVC9Bp1TOmsTRqquMUBcvKBWUto2dxGuqnjfQLgEfxLGOhK98EDff1tATP5eZ-7aONvlIhrDU" +
      "yKqCgZLUnvVi3s7qE\",\"q\":\"0we8TQ8ivTdp9wkGfuyu5f4zCQFuFsyVdO8jEd77m2ZWumBpYpYvV34Lg9IqeiRtNX8pQ-Hi8QIKXhnAE" +
      "55-KU-emgSJVtR_50da59BTq-VD0heCBhuTA6aDCu3Yb9chbRcxlIIp-GJlS2sRisoGzlgKgwAw5fkhnj7DXdL0CzM\",\"dp\":\"PVovgnd" +
      "_l67bmlC4F_4Lstq-tFpuZFpto7hkaWg-rkKJ_VHuW8FTVBDR02U0IRrFjwuYJOZh74x1Z80-kUJA1j8GTmcva21Ppsmi5SxzyWbwPzkU2VVc" +
      "x01ZoACKNt_0QdM315sa3hmj7OQujIplOG75ZfET71FQF-iABbTtQmE\",\"dq\":\"AZS-QWmKnhZLMfGcXdkSGmEEKt4a4AraV8zu21RrWC" +
      "e1IKJWR8nOQv6LwYoSjWW2d78jJQINPDcCst_Ig50dXtvc2VSNXtwqtSXgtXnnFpOaJXnNnJQaTt2xf6R2iaf39SRGV9F91QGPtrfvorWOxX7" +
      "9XSvkMeTi7peTySEqeOc\",\"qi\":\"ENCxJaHcPIBu5JObYrt0Qf4ZEj2aEFMOdtbijj8Eykx4XD6I-sosG1XWfKl6JV3-fR8OwTyS_KZyj" +
      "0dEOtpRSkM3bzuc24WMt3xt7pkf7uCjTU9H_rX475cf5wog7f1qQHdy3FkCqAgXTBThPCrObWKBQKGQRTD-rzUKZMu4Qmk\"},{\"kty\":\"" +
      "EC\",\"kid\":\"y-d_6-Q\",\"use\":\"enc\",\"x\":\"6vuZ4sXwcZakG-to24OTl9ausKXBwhJ07wPzcYPamMc\",\"y\":\"S5oijw" +
      "bmu6323BE1nyxsLALR5cvjKisLmPVmrlMOkvg\",\"crv\":\"P-256\",\"d\":\"WGbj9NHJi32wFKCCDdlaTg4Wz4A3iOwz2GTJmLM6Tq8" +
      "\"},{\"kty\":\"EC\",\"kid\":\"MShX4q0\",\"use\":\"enc\",\"x\":\"ERK0_wI9OC_vPvWTgN4CSgoZjuSVne599eI3rucN_I5ie" +
      "Opm823fXAidM3hisQ0z\",\"y\":\"G3ez7AwleHtpDSF4yv29_wmZQmQJaoJEXFFlzw40rGPVsrIVM8EaAkCExR2vL1Ln\",\"crv\":\"P-" +
      "384\",\"d\":\"j7s4vyEhlhdQaY0XiMf018AtIzxvov0nPVw8M3BCwiTYl0q-dkjlWOvQh_ShSE5b\"},{\"kty\":\"EC\",\"kid\":\"2" +
      "biZ7iQ\",\"use\":\"enc\",\"x\":\"ASPDR6Z0yPPf5WQ1vrg4hDwCG7nCna2AhkwvVlrIi3THrouRaIyPfvfDyJ7_kGvxulpqivLdHaeP" +
      "4FGqO0FZYjaO\",\"y\":\"AYe-9LyCnARzja54KxX6jymGMUg3r3jzw8PWaKopXh-KLYaMSVwybvggkOs6LSjgggVUaP3oY2OlygT6Fc7df3" +
      "TC\",\"crv\":\"P-521\",\"d\":\"ADMehHHdfUWURufhVzalzB5yp1z5XOGg0FP4kUKt4s7FQ82bB58ALxB1DgWc57HYeTk3-DQeoll8et" +
      "SDxbnBvRo7\"},{\"kty\":\"RSA\",\"kid\":\"U-DESNk\",\"use\":\"enc\",\"n\":\"idpTcmw_zbbL7GYHYnGXI5znbti4h4eBwo" +
      "v3qOYmCb-_Tl3yJLkff018nu9WLb7TFUC7sazfIIOvP6RVURLD5h39PwumJKZNtZ9qQZxjbaT3uWrEiDb9mb6UXW-zGU38f4XwGgqNfCdT1nB" +
      "mCprJsljVt12hqGEuMQGW5R5jalXnrAj-wGkuJQ2r5SN7THTelrmHEg37Ft-D8htO5ubUwMN4sslRICEX6FlB0yqG880tLK28j8EYftnDsKs-" +
      "bfS_md_pxq03sebMVN9pqcTC0bXh9q0_bXVGIWuzA3iAmKc-1ud36Gi0UPCfSdmbEHfywH60HXBK7jgBwR0aWu5w-w\",\"e\":\"AQAB\"," +
      "\"d\":\"eEoF1Ou2hShEK4UgXnumGdJZdLUx2DmbNgry0fP6LzmdkqGRoQ_U9z3DR-Cqv4IrKPlyjui9Tt75tjwMopEQViXHDRN6J7LiTmDL1" +
      "HLFpDB2ZdpPoljx1A2j4yCMFMGjWhei2uZobXTXyGAN-qT06WZxHu9aF9as-uBbLpTkxSzefHk4nUn7xQAzjr-Ab9Bf-kSTN5_DaMGRayhYBj" +
      "7taBfaNTTOTmNgTPMrK4PK9PPsqj9peI8kRLjqmoGC481e0YQL3M8j8-jpJ4KOyf1-ltqtcBUvl5rzOXtCRm-nopvg0iiQicwYhiIVHjCPGyU" +
      "Fu3SEHTtrOx2jYgt1X-wQYQ\",\"p\":\"69YuyA2FD8ZtyPUVmQsWM1v7O21ENQHt76VWbSKONQRMDSSqbwTwNpOM43ZOO1UY0iuaTCPIpjS" +
      "qEUq9Zeshzdk5EnmD8Bctwzju-1Mb0964i1A2G9sp2JuGfUMNGo2in48WgA9BC5X2wTBLwTtHJMp2HJWDF3GS37UMJhOE2gs\",\"q\":\"la" +
      "OL3EChEHKZWSU_q8v7dxRQcYX3n1JTfCZxJbopio_jTtQ0j5JDjsci0_emix7uXT3gQEtqEiAVZ5kE866nFJXEXdlYGdYD5Fv8geO8oc7PGnt" +
      "s1LfWQ5kpBGmdfsnGToqdDz21aW5ZLlTn0bIcpIq-QH1-bCvDc0w70v1cCtE\",\"dp\":\"qMgdrPD4FOUnNxYoAeLMXa9rqwk1MlaSKduDc" +
      "hG0Ar9zikh-bXv0SqrovvWxYYcyf1_TSsClXkX8nOmHiQRxqffXf6BVy6NbDgeWCWpeVRBltNaQEvmUBkCwTL-LBkDtbRIjwTypiZgnA_YDkW" +
      "RSM0NuqmBadJHE0rOo4StA_ic\",\"dq\":\"Cwhj53lcZroMVGZKq3_-qmj1BWm7OCP5w82RyhZPuceiGs3KkktWb9B-4OIBhYBiUr2dKyBk" +
      "UbHL4jeGBfF6oCnqsIC13jHJV6zwkSMZZVS6MFmpTIXBZnqEa67dzdtSo7fUnKsQFRXtvVzFOtDHC9qu7FJUX-VaI8YbIxNLFgE\",\"qi\":" +
      "\"0shcudMZNYYqZyqUmzewV-CWQZ3-ZGv7Ba323bytigATnRRGx6w7QDB-JILxCTlHpU3zNDcuE-kGKWZIvQiZEmXjSsUOlzQsv-QB5ZIM44R" +
      "NP8KScYSt1X8ud1GlOT9th4tUNYjqV1XBLZ-IjD3ogxoiaSZ1u_GSoN2CWnpH1Xg\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(`RSA-OAEP`),
          keyID = Some(KeyId("U-DESNk"))), None, None, empty, empty, empty, empty, None)))
        keys2 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(RSA1_5),
          keyID = Some(KeyId("U-DESNk"))), None, None, empty, empty, empty, empty, None)))
        // kid for an ec key
        keys3 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(RSA1_5),
          keyID = Some(KeyId("y-d_6-Q"))), None, None, empty, empty, empty, empty, None)))
        keys4 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES`),
          keyID = Some(KeyId("rSK-0_k"))), None, None, empty, empty, empty, empty, None)))
        keys5 <- EitherT(jwks.decryptionPrimitives[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES+A128KW`),
          keyID = Some(KeyId("y-d_6-Q"))), None, None, empty, empty, empty, empty, None)))
        // kid for an rsa key
        keys6 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES+A128KW`),
          keyID = Some(KeyId("__8lh94"))), None, None, empty, empty, empty, empty, None)))
      yield
        keys1.length == 1 && keys1.head.key.isInstanceOf[RSAPrivateKey] &&
          keys2.length == 1 && keys2.head.key.isInstanceOf[RSAPrivateKey] &&
          keys3.isEmpty &&
          keys4.length == 1 && keys4.head.key.isInstanceOf[ECPrivateKey] &&
          keys5.length == 1 && keys5.head.key.isInstanceOf[ECPrivateKey] &&
          keys6.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetFilter" should "succeed with some kid symmetric selections" in {
    val json = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"1gfpc39Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"},{" +
      "\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"9vlp7BLzRr-a9pOKK7BA25o88u6cY2o9Lz6--FfSWXw\"},{\"kty\":\"oct\",\"ki" +
      "d\":\"tres\",\"k\":\"i001zDJd6-7rP5pnldgK-jcDjT8N12o3bIjwgeWAYEc\"},{\"kty\":\"oct\",\"kid\":\"quatro\",\"k\"" +
      ":\"_-cqzgJ-_aeZkppR2JCOlx\"},{\"kty\":\"oct\",\"kid\":\"cinque\",\"k\":\"FFsrZpj_Fbeal88Rz0c2Lk\"},{\"kty\":" +
      "\"oct\",\"kid\":\"sechs\", \"k\":\"ad2-dGiAp8czx9310j4o70\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(dir),
          keyID = Some(KeyId("tres"))), None, None, empty, empty, empty, empty, None)))
        keys2 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(A128KW),
          keyID = Some(KeyId("quatro"))), None, None, empty, empty, empty, empty, None)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("tres")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("quatro"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetFilter" should "succeed with key ops in selector" in {
    val json = "{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"sign\"],\"x\":\"QPd8QUsROHjClFvQENhc-UXaaTBC-s10b50sD2B1WU" +
      "o\",\"y\":\"bz4xdwK8Edtm9HREbLy7EI9mzg-rUAUVosK5ybFLaRA\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"key_ops\":[\"" +
      "sign\"],\"n\":\"gxhgbcxZcQ_AHMFuaKJsWNRDh4kKN2CRdMQwhvUyw9brriPomDcGIVSpeq1iiPPd56umWXLF6TgxbVFsqxH7lTh013F8S" +
      "SYg8pOQ3YYbg-JLJoVWEQZwVsBwzHXvjW4qXyfWMCyBD6p7ta_2LEZjkvVCAVaoTLjK8_1fl3Njj2d-kAzIyKC3mBWajuu51jH2tmCV_CKj7M" +
      "qShO0Wa7UqNyVtLIiKqApi-be1D_s9dzgPBbAAwJ3qJy4g74Q5cBfVUaJ9QpqKIWYuITuD02IzSpapckqKeF6vfCuZkS9hwBr4vviY2rTLzVR" +
      "nVlvKkUek4084qa9arZTF8uLnyiSiVw\",\"e\":\"AQAB\"},{\"kty\":\"RSA\",\"key_ops\":[\"deriveKey\"],\"n\":\"kGWRVJ" +
      "UV2J6Bg96M37BUIeBj0O16sraxlwZBmeTC4xPKEbOGLgBMfm_7DpwbhpS2jioLp54ldyDqVXmEphWQecnHGCT3uWaAv9CbARpOPOL9FRzuQrY" +
      "DSMRjoY4S_nlL3nAC8lNros48APoj6XwAQVo-cIcjJSpMNJUSLIE0dNLk9067zxugEG5ljX7IHFe0GpAZWUyb5W3VlQOAEgYoguxgtJIyatfp" +
      "GTxkpLbEO8lo6OGnJMFrykdUejUTpUY3u_5rAPXLr37M676nblZGxHCB5mgRxGig9EqKEbDbWyuwkHCQspvconhMPGYBB2t6cptTQTt-h8XOC" +
      "d0nYIK_vw\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"key_ops\":[\"deriveKey\"],\"x\":\"E7i5NiWEyw5GPFFtxKjWhT12rqRN7" +
      "dbtvRAtdmxOoKs\",\"y\":\"y77a93eutsPWgyqKvDpHoN0XbIJ_rGB4DMd9sVF378o\",\"crv\":\"P-256\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        second <- EitherT(IO(jwks.keys(2)).asError)
        secondKey <- EitherT(second.toKey[IO]())
        third <- EitherT(IO(jwks.keys(3)).asError)
        thirdKey <- EitherT(third.toKey[IO]())
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES+A128KW`)), None, None,
          empty, empty, empty, empty, None)))
        key1 <- EitherT(keys1.head.toKey[IO]())
        keys2 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES`)), None, None, empty,
          empty, empty, empty, None)))
        key2 <- EitherT(keys2.head.toKey[IO]())
        keys3 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`RSA-OAEP`)), None, None, empty,
          empty, empty, empty, None)))
        key3 <- EitherT(keys3.head.toKey[IO]())
        keys4 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(dir)), None, None, empty,
          empty, empty, empty, None)))
      yield
        keys1.length == 1 && key1.equals(thirdKey) && keys2.length == 1 && key2.equals(thirdKey) &&
          keys3.length == 1 && key3.equals(secondKey) && keys4.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetFilter" should "succeed with use in selector" in {
    val json = "{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"QPd8QUsROHjClFvQENhc-UXaaTBC-s10b50sD2B1WUo\",\"y" +
      "\":\"bz4xdwK8Edtm9HREbLy7EI9mzg-rUAUVosK5ybFLaRA\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"use\":\"sig\",\"n\":" +
      "\"gxhgbcxZcQ_AHMFuaKJsWNRDh4kKN2CRdMQwhvUyw9brriPomDcGIVSpeq1iiPPd56umWXLF6TgxbVFsqxH7lTh013F8SSYg8pOQ3YYbg-J" +
      "LJoVWEQZwVsBwzHXvjW4qXyfWMCyBD6p7ta_2LEZjkvVCAVaoTLjK8_1fl3Njj2d-kAzIyKC3mBWajuu51jH2tmCV_CKj7MqShO0Wa7UqNyVt" +
      "LIiKqApi-be1D_s9dzgPBbAAwJ3qJy4g74Q5cBfVUaJ9QpqKIWYuITuD02IzSpapckqKeF6vfCuZkS9hwBr4vviY2rTLzVRnVlvKkUek4084q" +
      "a9arZTF8uLnyiSiVw\",\"e\":\"AQAB\"},{\"kty\":\"RSA\",\"use\":\"enc\",\"n\":\"kGWRVJUV2J6Bg96M37BUIeBj0O16srax" +
      "lwZBmeTC4xPKEbOGLgBMfm_7DpwbhpS2jioLp54ldyDqVXmEphWQecnHGCT3uWaAv9CbARpOPOL9FRzuQrYDSMRjoY4S_nlL3nAC8lNros48A" +
      "Poj6XwAQVo-cIcjJSpMNJUSLIE0dNLk9067zxugEG5ljX7IHFe0GpAZWUyb5W3VlQOAEgYoguxgtJIyatfpGTxkpLbEO8lo6OGnJMFrykdUej" +
      "UTpUY3u_5rAPXLr37M676nblZGxHCB5mgRxGig9EqKEbDbWyuwkHCQspvconhMPGYBB2t6cptTQTt-h8XOCd0nYIK_vw\",\"e\":\"AQAB\"" +
      "},{\"kty\":\"EC\",\"use\":\"enc\",\"x\":\"E7i5NiWEyw5GPFFtxKjWhT12rqRN7dbtvRAtdmxOoKs\",\"y\":\"y77a93eutsPWg" +
      "yqKvDpHoN0XbIJ_rGB4DMd9sVF378o\",\"crv\":\"P-256\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        second <- EitherT(IO(jwks.keys(2)).asError)
        secondKey <- EitherT(second.toKey[IO]())
        third <- EitherT(IO(jwks.keys(3)).asError)
        thirdKey <- EitherT(third.toKey[IO]())
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES+A128KW`)), None, None,
          empty, empty, empty, empty, None)))
        key1 <- EitherT(keys1.head.toKey[IO]())
        keys2 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`ECDH-ES`)), None, None, empty,
          empty, empty, empty, None)))
        key2 <- EitherT(keys2.head.toKey[IO]())
        keys3 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(`RSA-OAEP`)), None, None, empty,
          empty, empty, empty, None)))
        key3 <- EitherT(keys3.head.toKey[IO]())
        keys4 <- EitherT(jwks.filterForDecryption[IO](JsonWebEncryption(JoseHeader(Some(dir)), None, None, empty,
          empty, empty, empty, None)))
      yield
        keys1.length == 1 && key1.equals(thirdKey) && keys2.length == 1 && key2.equals(thirdKey) &&
          keys3.length == 1 && key3.equals(secondKey) && keys4.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebKeySetFilterFlatSpec
