package com.peknight.jose.jwt

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwe.DecryptionPrimitive
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jws.VerificationPrimitive
import com.peknight.jose.jwx.JoseConfig
import com.peknight.jose.syntax.x509Certificate.{sha1Thumbprint, sha256Thumbprint}
import com.peknight.validation.std.either.isTrue
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.Bases.Alphabets.HexUppercase
import scodec.bits.ByteVector

import java.security.cert.X509Certificate
import java.time.Instant

class X509CertificateVerificationFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  private def initKeyList: EitherT[IO, Error, List[X509Certificate]] =
    val j0 = "{\"kty\":\"RSA\",\"n\":\"v5UvsMi60ASbQEIKdOdkXDfBRKgoLHH4lZLwUiiDq_VscTatbZDvTFnfmFKHExTzn0LKTjTNhKhY8" +
      "1CNLTNItRqmsTZ5cMnR0PTS777ncQ70l_YxAXxpBWANOkEPzRMbF4R7d9GBJQUzKgVVWvGH_6BG-oSuDMc82j3rInMp38T-afcf3F9gcpfhEL" +
      "M1xChfjaMyExLezhPi2F4O41z9kWpHF3hYwu-h_xuJA_apc2gPf1RvpB6v2m4ll4QdnQIu1MIb_8z7018OWdCIUf2sGVepnHosiNxfdhmu9br" +
      "wXSbYcbWVJUdmhB5bZze3af5nI4qtX_BV_YPgsfsczAKmuQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIDKDCCAhCgAwIBAgIGAUqtA+agMA0GC" +
      "SqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxFzAVBgNVBA" +
      "MTDkJyaWFuIENhbXBiZWxsMB4XDTE1MDEwMjIzMzg0MVoXDTQyMDgyNDIyMzg0MVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQY" +
      "DVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
      "AoIBAQC\\/lS+wyLrQBJtAQgp052RcN8FEqCgscfiVkvBSKIOr9WxxNq1tkO9MWd+YUocTFPOfQspONM2EqFjzUI0tM0i1GqaxNnlwydHQ9NL" +
      "vvudxDvSX9jEBfGkFYA06QQ\\/NExsXhHt30YElBTMqBVVa8Yf\\/oEb6hK4MxzzaPesicynfxP5p9x\\/cX2Byl+EQszXEKF+NozITEt7OE+" +
      "LYXg7jXP2RakcXeFjC76H\\/G4kD9qlzaA9\\/VG+kHq\\/abiWXhB2dAi7Uwhv\\/zPvTXw5Z0IhR\\/awZV6mceiyI3F92Ga71uvBdJthxt" +
      "ZUlR2aEHltnN7dp\\/mcjiq1f8FX9g+Cx+xzMAqa5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABwJ7Iw904nf4KiTviWa3j3OWauSOV0GpM\\" +
      "/ORJbsIvqUada5VubOrN0+NRQJm3\\/TTFOIsvRqL86cpFf7ikpdfLjyKR\\/ZQVrop9yoCPQAiLe7IcPozngaLoHOK2OcEWRDbxPfBnhmxfy" +
      "GqMxtXuqVIEIQ40AIjdimHgbTbmaMQIZpANgHryfJDrQJX2UXnqgtCYaJzoLJMFY7BrlO8mCSez8V886DpbTzXYJwDk4GCDYUTEvNUbFVvpVo" +
      "WaYX2JtwP1fm+lQtiKhHyp1PCJh\\/5Ijbf6sTlONXWVSreWw6LKjixM\\/HNJnK5Yd3vSql\\/nwI3Cy2kGgzjCzUfcyQ\\/LU+2tI=\"]," +
      "\"d\":\"Df2lF_HwwpQzikPIY7UqPRnNQWhOVsCT-MhcSIOw6fPoUXQ-wgudjiPaElOkjZ4wFGdaQs_UWmW46Tvus2hVXPRvS-3AfJ4gdnQKm" +
      "3uDh1wiPJ68AXHGcaAMFz79GmrUxajlI2DnX367t8vf6d5NojtgM5dQ5pn-Nanj7AYg_rhRjGjK783PepBCAHQ2zwdGBHaS_1e4IErtyCFiJN" +
      "405O6_jacmdIEPATSNNItnrGVTDQjCI0hswVqXeOr2pUEDLWuXEcKS-0xZ4T1MV1MDipoNy4EtxHrQrXd32aY7IIp3QMWAgxeES24dSZRhdFI" +
      "CFPEhNb_jq88bpaGR6sbLAQ\",\"p\":\"-oaNOH47V97ZhC-YkPIpmVXVWVLmna1_dy_eBGpMqgITVyYJIBEY7S6BSEhm9bTLayCL_tePv3b" +
      "gzzzusE2sAVcc-0ifoE2tFMi3gpk9130xEjQwDmFXcddCfjKbqf4nJWrmfTqAGIOu2A4JGozqcLRJdxbtDpP9X8Nk5vN52jE\",\"q\":\"w8" +
      "ToEQ64_Hfxd-gnMyR4rI6jnnOlD884M3APYK8tHcux19n37zgEF29h9cn4h5Kyfs0x90ThGLtPPthCphqdS6K5v50X7A6p43GwojK9Ut2JT8F" +
      "Zxo6dlBBxtElE481sL832f_nBBpik9stz_JJvg89BvSNnjIldBmbfaG2f6wk\",\"dp\":\"N-7iiMJmLXAr0D9wKKxobTukrpS7uGiMFOgzA" +
      "XlaNHrSJprvXqFyl0HSy3iexCzhXcGef_9QsMax2pMYF3S_-mygo9nLCddN1V4a2qWsEPh6hD3ynMNO6rPMvLA_4OxFgS0k2MC-6Lo9xy8bCT" +
      "p8_TzDSjtsId0YrNDLLmUdx4E\",\"dq\":\"Vyc6CR38zKi5HyCDEwmRj4CQ5uGlAjzGUF_6-JgEBdfA_M9UyXKun6A-hCW-NtzgCgNf0y0e" +
      "6Nu6k8fDJB-FFz8CYoOVOsnsaA0dDZh5IILvtknlpben_1qyxAg6WxAAseeHbcHKZR1fk19P64lli9Cg-4rfdnlQqKDzpJHpN8E\",\"qi\":" +
      "\"8OHKueEcRf0KpoWmowEI4IFZRTZoSxDNxFlA5J0E5nMtqKxOLVVKn_wOQsUK1u4UOn4ull7ZbbRMZRhOLnVyggpHgJ7BN9hmiYUgN7qJx9P" +
      "xSz0AZTUpX-FIP5V4p30tspPvfCHsbvZ2Sq-sB6BaPzV33W1X-Uc2kfl4EOsV-nA\"}"
    val j1 = "{\"kty\":\"RSA\",\"n\":\"neaZ2O9Auht0ZASyP4wr_kTkIis1QQkFXTD-gW9sXJQhYb6sISSGt_uu5lPZTcbLfIyROLgjWLcG7" +
      "lPQ6dxbKtcU51wiFWLYu4Qjvk7zD17YJQD8xH0j5dzyo7zJqLbJjY3a32_V9K6r3O-MpGObH7BFs_PokvQkNHYIgwQR2KJfH_LDihRBcNV4pj" +
      "rRa2qyeEjH5-wd21AqJdPgKnW-o92xGU-G71Qk6qOdjMDYnlXMEwvtxBssi22cgAlSAcW0p4pFUQWQUxahAND_LdACc-iGxLMxtvddJ9pxQxg" +
      "BW8qQJratiwjCpYBVCB6Gw9uA76Ee65lF3fp8ldUt32mzCw\",\"e\":\"AQAB\",\"x5c\":[\"MIIDNDCCAhygAwIBAgIGAUqtD7sRMA0GC" +
      "SqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxHTAbBgNVBA" +
      "MTFEJyaWFuIERhdmlkIENhbXBiZWxsMB4XDTE1MDEwMjIzNTEzNloXDTQ1MDUyMDIyNTEzNlowWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkN" +
      "PMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEB" +
      "AQUAA4IBDwAwggEKAoIBAQCd5pnY70C6G3RkBLI\\/jCv+ROQiKzVBCQVdMP6Bb2xclCFhvqwhJIa3+67mU9lNxst8jJE4uCNYtwbuU9Dp3Fs" +
      "q1xTnXCIVYti7hCO+TvMPXtglAPzEfSPl3PKjvMmotsmNjdrfb9X0rqvc74ykY5sfsEWz8+iS9CQ0dgiDBBHYol8f8sOKFEFw1XimOtFrarJ4" +
      "SMfn7B3bUCol0+Aqdb6j3bEZT4bvVCTqo52MwNieVcwTC+3EGyyLbZyACVIBxbSnikVRBZBTFqEA0P8t0AJz6IbEszG2910n2nFDGAFbypAmt" +
      "q2LCMKlgFUIHobD24DvoR7rmUXd+nyV1S3fabMLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI94fDaieGwkj1dDSEM+2TJwrciMGdUM8EgMeW" +
      "sVQgTS+xfkmvP5fjYW78eQ8072lYfkodsyC00hsUl8LFzsVKbAgU\\/+GQCVwd++JdguC8g3186cp2l6WxPHYFkCJs3QGEnarMIeD42dBjIB2" +
      "HueOJ5rDKz6sC2g2c2lC7rTs662HPztPY9dRYLxWmy47C4YdPcn8toNatQjkC3j+w3K5QWZe5tf1X6C0xClmss8WyI+qJV13aPjHu8ybYJec5" +
      "jryzKr9qT\\/t2YOzrvszkNTrUNFz4JCD9LXM0Vl5gdp6QOBSzwzhMeZcGJCQRuJa8fo\\/sCsoZFNzuNtmc5N2b5jxXQ=\"],\"d\":\"lOH" +
      "0OioNW-27JvuOnoCqkouel-Epy3KYDjC-KIlJIVnCyAki__US2bOETETPZpiFEaDw5Qwqt-GLtXhuSbOueoxmd2fV81hKhzSnBzAl2l5Ra0Kt" +
      "Ew_zoy9b0auWcXA4RzJ0J62pjZaNEjsE35PTlmN8tZrLtpRg9t48VFyn_xxLMNth3SDn36jVpeCI5KZEitwaVzi5nnYONfpLT9v_iD8GRu1zU" +
      "KeuXMbMbEcQW8WaoPQmPgrqaf7YD8apfS_6o5VQhl4SnY6mDnd1DnU3XnVS3JgNV5CKUZek1Tb27b6Z1YVpowgWcBQqXZz21pNVgDUrh8opLG" +
      "Z1aFFgTBz38Q\"}"
    val j2 = "{\"kty\":\"RSA\",\"n\":\"7LnNihjvihRLAHlwPC4rTAI-ToPNspm-QV9UTrNSYTdL_DePpuvWqis8iqOnWNzjTTQgBj__D6fjz" +
      "7gdKnsdUtHT0H70inY92kU96MJaiIQol9ZxrGfjIumejOcbEkAmmfrMKPASl4US_NpcPYMtFzjJ3txNm6cgAVzYdZEmtW1vVa86etICUDQ_eD" +
      "3bpHY4vcWB7m8slnnZ4JFbojDsfJUhTEuHzr_rkXI6XVrdv8kPnbEBK7dfbZVlcguQ1nFCiIUY4MO8f-zF7rF3d3AvqtxmQqNT_L1a67O0aoP" +
      "ldNmFJ0nl2hKywKwhx52fMT8VUqAT_W-aY-Ody-H8GWZBqw\",\"e\":\"AQAB\",\"x5c\":[\"MIIDLjCCAhagAwIBAgIGAUqtEXLzMA0GC" +
      "SqGSIb3DQEBCwUAMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxGjAYBgNVBA" +
      "MTEUJyaWFuIEQuIENhbXBiZWxsMB4XDTE1MDEwMjIzNTMyOVoXDTQzMDYyMDIyNTMyOVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8" +
      "wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEaMBgGA1UEAxMRQnJpYW4gRC4gQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IB" +
      "DwAwggEKAoIBAQDsuc2KGO+KFEsAeXA8LitMAj5Og82ymb5BX1ROs1JhN0v8N4+m69aqKzyKo6dY3ONNNCAGP\\/8Pp+PPuB0qex1S0dPQfvS" +
      "Kdj3aRT3owlqIhCiX1nGsZ+Mi6Z6M5xsSQCaZ+swo8BKXhRL82lw9gy0XOMne3E2bpyABXNh1kSa1bW9Vrzp60gJQND94Pdukdji9xYHubyyW" +
      "edngkVuiMOx8lSFMS4fOv+uRcjpdWt2\\/yQ+dsQErt19tlWVyC5DWcUKIhRjgw7x\\/7MXusXd3cC+q3GZCo1P8vVrrs7Rqg+V02YUnSeXaE" +
      "rLArCHHnZ8xPxVSoBP9b5pj453L4fwZZkGrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEL302pFrgsVDleaME1BvtTmZvE9ffBpiOc8k6kUpg" +
      "30\\/I\\/ptXVHbMXcCLckn8OEclp8yf\\/8KgD0tZ5Sb501ucfYKWOKR1WBR1QunnLgzKiNflnZzITrXWI+cfwiJwn\\/PE2M5975dTDGeyz" +
      "pGB6Tfn7HrfdLfoyMk5+rwehfG5\\/vX82fCZLM6NbxViaXJSud9hCVbxJEvvTUlVmVOrWhuebBJbtut4+RfI0RMm3AwYmRqZmnmNV85HZ9J5" +
      "li7CoPHE9UHxxR8R8GWnsjQuB5og50FpGTub7OkyFTCnYSAUxmZYk4Z1BN8zMOD+JKOa5kZINouifPiwtXjq4aL7YCBUc=\"],\"d\":\"R8h" +
      "75FF1abiHmcg5WXZimLThceuT14G5aJdguFC2PVaISx4KCILhYE6mGCBSIacxofqZb2u-i1_Mu_NHnNciaDfKdCHbQ5VhYiu2_zrYOydgK9LS" +
      "O4ZxIOgYtP9rfRhI3E5p1EwgRyQKQvRwHhMF_FGzHUpOmlGOaftehCAUzdShLfZdNp93ohpqamal1uisx9dbGqI1vX5_mQpvoH2OGBIhlVbp5" +
      "EKMqib724y3GLOrbYgJDM_Z1BRNNSy51oceXieV7GcX-oT2Xv3YZfsLyM8JSZJzIiSl6_bykvGSxRv3E25JrtHtX9GDpE0YdatXm030_o2TjW" +
      "tIfBZPabE5mQ\",\"p\":\"964kN9rx7_aWNj3vYHEkD4f_ka-JRDQknBgIdkK6use7oe6WE0iyhJolNemJRwB_JpAQ9kBfYjoyqgv_22tTvD" +
      "AqU75uTm8mhvsefPxur-khp4IuUfwhbvT7GfR45-fbpubf8ic0IZ-PM6tc3mAYV4KEOGk4proUTO1FHYK8Yx8\",\"q\":\"9K12LZkuTK80E" +
      "E1e7Z9QuOMR_kl4UUWDaJUmGMxI6Dh5EZ60Ny2jja3-vAzBxknfxopQpQa4A77ePTCChHBEw5uCC7AZAmeIuU2qqb1XZd2_7CBkJjsyxEr09e" +
      "XDzy4sEqME9Ql6kCC6XZQ2LikmQuLvS7VddEMrdez90wiU-_U\",\"dp\":\"NJWaRumLGCFIPvfjTJx4xXtgPTQBdqODakiH82OzdVhWc8jN" +
      "wAZdMF3xrIKKjLKETFGl6EI-fgJRI10s0w70Vi37ro_tp2VdzqaeEHcfoOVkKcYvw2Q-TOpiLV6EFOha8BJwVV8RaFoR8yxcqTHJuTqSi897I" +
      "Zq8GKD_XYaWLI0\",\"dq\":\"LOygczTZ5zGiS1Z9vG5AR4TCIADl7JujtfMlNymXPyRt9VzfdfPgbPItC50IsXfz4YlrI_dPi-4UTBwceH7" +
      "UBWyz1TrIRlXhvCR7yg-Ho5yI09-TmnoJmCtZ8bZ23OxYOL4nRAjCwWUA5F6971zPk-4jxSORO-WbP1wIhhJrhx_U\",\"qi\":\"F7hzNEUa" +
      "uVSoyi9xSmp7uHSIHE3BiPMq-__Z1fZ7oODk3kmJeFzw3Jx5g8NaHsixA7DPb-aQ2Y_XPZPL28EuJqz2bbGguK9pAvwhqAPTZoNjWpJe5Ds5h" +
      "L5dvGIxvvSLlZdgQmxzfsU_e1LtE5vae1kd5RxZgjcZ5Ssn9rBJBlQ\"}"
    val j3 = "{\"kty\":\"EC\",\"x\":\"bhH1zISTvaqIluqvQHcVXNVkf-oJlo3MXI34TvPpn0Y\",\"y\":\"a2oX03bfUpSd8IOwnZja1NId" +
      "yITxWuFiBjnJV9pRPbQ\",\"crv\":\"P-256\",\"x5c\":[\"MIIBoDCCAUSgAwIBAgIGAUqv7HETMAwGCCqGSM49BAMCBQAwVTELMAkGA1" +
      "UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJlbGwwHhc" +
      "NMTUwMTAzMTMxMTU1WhcNNDMwNjIxMTIxMTU1WjBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEPMA0GA1UE" +
      "ChMGam9zZTRqMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG4R9cyEk72qiJbqr0B3FVzVZH\\/" +
      "qCZaNzFyN+E7z6Z9Ga2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQwDAYIKoZIzj0EAwIFAANIADBFAiEA7s85afZ5+ROkthajh87x" +
      "g89spz8lzDmGolzPfbuPULwCICZC1q3Xyk70KKpZWpXaSlu0bfMkuNwG7RtMPv+ao+zb\"],\"d\":\"81bMjwCNiMA8ZVRGSXkf9nSGvZ-uW" +
      "TcFTZCu3S8TvAw\"}"
    val j4 = "{\"kty\":\"EC\",\"x\":\"3CpPM7n0EwqENMDNKuDMkx5nNZ7F9xQKJ1FJ7XQY7Os\",\"y\":\"_B-nBJwT7Qsdv3RpAIZY-1Na" +
      "ZgzE-Mdu_CsWJ7LBDxk\",\"crv\":\"P-256\",\"x5c\":[\"MIIBqjCCAVCgAwIBAgIGAUqv7n85MAwGCCqGSM49BAMCBQAwWzELMAkGA1" +
      "UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJ" +
      "lbGwwHhcNMTUwMTAzMTMxNDEwWhcNNDgwMjEyMTMxNDEwWjBbMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEP" +
      "MA0GA1UEChMGam9zZTRqMR0wGwYDVQQDExRCcmlhbiBEYXZpZCBDYW1wYmVsbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNwqTzO59BMKh" +
      "DTAzSrgzJMeZzWexfcUCidRSe10GOzr\\/B+nBJwT7Qsdv3RpAIZY+1NaZgzE+Mdu\\/CsWJ7LBDxkwDAYIKoZIzj0EAwIFAANGADBDAh8N9c" +
      "KJYRq8kMmbpoqaB6PT\\/uVPK++RxBy5SWqCl0y1AiAQJfMfQJxZBZ0iCNYcpFmTpXIPaVxu50XHqafQETYQBg==\"],\"d\":\"LzVM5880b" +
      "eqKgVOnrab4PCNiIEpaUa8niRaOsZY0apc\"}"
    List(j0, j1, j2, j3, j4).traverse { j =>
      for
        jwk <- decode[Id, AsymmetricJsonWebKey](j).eLiftET[IO]
        cert <- EitherT(jwk.getLeafCertificate[IO]())
      yield
        cert
    }.map { _.collect {
      case Some(cert) => cert
    }}
  end initKeyList

  "X509CertificateVerification" should "succeed with x5t stuff" in {
    val jwt = "eyJ4NXQiOiJaYjFIVDdyeUNSQUFqMndjUThoV2J6YXFYMXMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIs" +
      "ImV4cCI6MTQyMDI5NjI1Nywic3ViIjoiYWJvdXQifQ.RidDM9z0OJkfV2mwxABtEh2Gr_BCFbTuetOTV_dmnFofarBK7VDPPdsdAhtIs3u7WQ" +
      "q9guoo6H3AUGfj4mTFKX3axi2TsaYRKM9wSoRjxFO7ednGcRGx8bnSerqqrbBuM9ZUUt93sIXuneJHYRKlh0Tt9mCXISv1H4OMEueXOJhck-J" +
      "PgLPfLDqIPa8t93SULKTQtLvs8KEby2uJOL8vIy-a-lFp9irCWwTnd0QRidpuLAPLr428LPNPycEVqD2TpY7y_xaQJh49oqoq_AmQCmIn3CpZ" +
      "LDLqD1wpEPxLQyd1vbvgQ583y2XJ95_QufjbRd2Oshv3Z3JxpIm9Yie6yQ"
    val run =
      for
        certs <- initKeyList
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfig(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF)(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        (jwtClaims2, nested2) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(certs))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1420296253L)).eLiftET[IO]
        _ <- jwtClaims2.expectedAudiences("you").eLiftET[IO]
        _ <- jwtClaims2.expectedSubjects("about").eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(certs.zipWithIndex.filterNot(_._2 == 1).map(_._1)))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "X509CertificateVerification" should "succeed with x5tS256 stuff" in {
    val jwt = "eyJ4NXQjUzI1NiI6IkZTcU90QjV2UHFaNGtqWXAwOUZqQnBrbVhIMFZxRURtLXdFY1Rjb3g2RUUiLCJhbGciOiJFUzI1NiJ9.eyJp" +
      "c3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5OTUzOSwic3ViIjoiYWJvdXQifQ.9Nj3UG8N9u7Eyu0wupR-eVS4Mf0ItwwHBZzwLc" +
      "Y2KUCJeWoPRPT7zC4MqMbHfLj6PzFi09iC3q3PniSJwmWJTA"
    val run =
      for
        certs <- initKeyList
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfig(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF)(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        (jwtClaims2, nested2) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(certs))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1420299538L)).eLiftET[IO]
        _ <- jwtClaims2.expectedAudiences("you").eLiftET[IO]
        _ <- jwtClaims2.expectedSubjects("about").eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(certs.zipWithIndex.filterNot(_._2 == 4).map(_._1)))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "X509CertificateVerification" should "succeed with both x5 header stuff" in {
    val jwt = "eyJ4NXQjUzI1NiI6InFTX2JYTlNfSklYQ3JuUmdha2I2b3RFS3Utd0xlb3R6N0tBWjN4UVVPcUUiLCJ4NXQiOiJpSFFLdVNHZVdVR" +
      "1laQ2c0X1JHSlNJQzBORFEiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5OTc2MSwic3ViIjoiY" +
      "WJvdXQifQ.04qPYooLJN2G0q0LYVepaydszTuhY7jKjqi5IGkNBAWZ-IBlW_pWzkurR1MkO48SbJQK2swmy7Ogfihi1ClAlA"
    val run =
      for
        certs <- initKeyList
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfig(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF)(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        (jwtClaims2, nested2) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(certs))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- jwtClaims2.checkTime(Instant.ofEpochSecond(1420299760L)).eLiftET[IO]
        _ <- jwtClaims2.expectedAudiences("you").eLiftET[IO]
        _ <- jwtClaims2.expectedSubjects("about").eLiftET[IO]
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(certs.zipWithIndex.filterNot(_._2 == 3).map(_._1)))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "X509CertificateVerification" should "succeed with no thumb header" in {
    // signed w/ 1
    val jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5ODk3OSwic3ViIjoiYWJvdXQifQ.HtKEt" +
      "mJOb5mmhHni5iJ0FUAEoNStpPZuFmQh7dtw-A7gIYsIUgdLumKCMgjG4OX_hDjvoSGl1XvHwYuzM24AohOJAaSdhLBnxTLZ4NumVwGLWp1uSj" +
      "Sy6stwkZrA3c9qLohLvib3RuX_x20ziOfA6YOMWwaAG66u93VwgG2upXBPwnySUuQYSPbFbSCTacoyJ9jTFu8ggeuI57dH34TyNXJK1F1Kow5" +
      "IRfsioyVHsT4mP4HRk6xLXOIclf3vsfPoAG9GR8jxpDYxKZXBrDqt8gnKefGcOe6lqQv1zS7Vrb6NO8ejVo5g5tkw5-Kbpu775ShB0-mHrMoc" +
      "rw1n8NmQlA"
    val run =
      for
        certs <- initKeyList
        (jwtClaims1, nested1) <- EitherT(JsonWebToken.getClaims[IO](jwt, JoseConfig(
          skipSignatureVerification = true, requireSignature = false))(
          VerificationPrimitive.defaultVerificationPrimitivesF)(
          DecryptionPrimitive.defaultDecryptionPrimitivesF))
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(VerificationPrimitive.x509Certificates(certs.take(2)))(
          DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
        certificateListList = List(certs.reverse, certs.take(3).reverse, certs.take(2).reverse, certs.take(2),
          List(certs(1)), List(certs(3), certs(1)))
        _ <- certificateListList.traverse { certs =>
          for
            (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](jwt)(
              VerificationPrimitive.x509Certificates(certs, true))(DecryptionPrimitive.defaultDecryptionPrimitivesF))
            _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1420298972L)).eLiftET[IO]
            _ <- jwtClaims.expectedAudiences("you").eLiftET[IO]
            _ <- jwtClaims.expectedSubjects("about").eLiftET[IO]
          yield
            ()
        }
        _ <- EitherT(JsonWebToken.getClaims[IO](jwt)(
          VerificationPrimitive.x509Certificates(List(certs.head, certs(2)), true)
        )(DecryptionPrimitive.defaultDecryptionPrimitivesF).map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "X509CertificateVerification" should "succeed with compare to open ssl fingerprints" in {
    val run =
      for
        certs <- initKeyList
        _ <- compareToOpenSslFingerprint("67:30:12:77:0B:B0:31:86:C4:19:57:79:04:FA:A2:79:FF:75:23:4B",
          "08:9C:BE:94:01:37:5F:46:AB:E3:87:0A:AF:12:9C:6A:E5:07:02:90:FF:92:D1:63:3C:2F:6C:E8:77:8E:C7:35",
          certs.head)
        _ <- compareToOpenSslFingerprint("65:BD:47:4F:BA:F2:09:10:00:8F:6C:1C:43:C8:56:6F:36:AA:5F:5B",
          "15:20:16:EE:C7:99:83:CB:A2:42:BF:75:0D:CE:D6:18:23:95:E3:A0:BE:5C:E6:4E:C9:EF:1A:E6:07:51:36:46",
          certs(1))
        _ <- compareToOpenSslFingerprint("0E:49:9C:40:CE:40:CC:3F:27:9D:03:95:E4:51:3F:63:5A:34:97:96",
          "6C:34:95:6E:9E:3D:D2:ED:EE:D7:DE:31:0A:15:FA:CD:76:FF:76:80:6F:9B:5F:CE:D4:F2:4C:F5:FC:5C:3A:20",
          certs(2))
        _ <- compareToOpenSslFingerprint("88:74:0A:B9:21:9E:59:41:98:64:28:38:FD:11:89:48:80:B4:34:34",
          "A9:2F:DB:5C:D4:BF:24:85:C2:AE:74:60:6A:46:FA:A2:D1:0A:BB:EC:0B:7A:8B:73:EC:A0:19:DF:14:14:3A:A1",
          certs(3))
        _ <- compareToOpenSslFingerprint("5B:C6:8E:F8:10:F6:8F:1F:4A:33:34:23:85:9F:39:BA:42:40:E5:98",
          "15:2A:8E:B4:1E:6F:3E:A6:78:92:36:29:D3:D1:63:06:99:26:5C:7D:15:A8:40:E6:FB:01:1C:4D:CA:31:E8:41",
          certs(4))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  private def compareToOpenSslFingerprint(sha1fp: String, sha256fp: String, certificate: X509Certificate)
  : EitherT[IO, Error, Unit] =
    for
      x5t <- EitherT(certificate.sha1Thumbprint[IO]())
      x5tBytes <- x5t.decode[Id].eLiftET[IO]
      sha1fpBytes <- ByteVector.fromHex(sha1fp.replaceAll(":", ""), HexUppercase).toRight(OptionEmpty.label("sha1fp"))
        .eLiftET[IO]
      _ <- isTrue(x5tBytes === sha1fpBytes, Error("sha1fp error")).eLiftET[IO]
      x5tS256 <- EitherT(certificate.sha256Thumbprint[IO]())
      x5tS256Bytes <- x5tS256.decode[Id].eLiftET[IO]
      sha256fpBytes <- ByteVector.fromHex(sha256fp.replaceAll(":", ""), HexUppercase)
        .toRight(OptionEmpty.label("sha256fp")).eLiftET[IO]
      _ <- isTrue(x5tS256Bytes === sha256fpBytes, Error("sha256fp error")).eLiftET[IO]
    yield
      ()
end X509CertificateVerificationFlatSpec
