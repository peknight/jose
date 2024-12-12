package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.`try`.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.ThumbprintMismatch
import com.peknight.jose.jwa.ecc.{`P-256`, `P-384`, `P-521`}
import com.peknight.jose.jwa.signature.*
import com.peknight.jose.jwk.JsonWebKey.{AsymmetricJsonWebKey, EllipticCurveJsonWebKey}
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jwt.JsonWebToken
import com.peknight.jose.jwx.JoseHeader
import com.peknight.jose.syntax.x509Certificate.base64UrlThumbprint
import com.peknight.security.digest.{`SHA-1`, `SHA-256`}
import com.peknight.validation.std.either.{isTrue, typed}
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import scala.util.Try

class JsonWebKeySetForVerificationFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKeySetForVerification" should "succeed with unique kid tests" in {
    // JSON content from a PingFederate JWKS endpoint (a snapshot build circa Jan '15)
    val json = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"zq2ym\",\"use\":\"sig\",\"x\":\"AAib8AfuP9X2esxxZXJUH0oggizKpaI" +
      "hf9ou3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\",\"y\":\"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wce" +
      "FFrvP2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"zq2yl\",\"use" +
      "\":\"sig\",\"x\":\"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\",\"y\":\"Bt0HwjlM4RoyCfq" +
      "7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"zq2yk\",\"us" +
      "e\":\"sig\",\"x\":\"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\",\"y\":\"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWi" +
      "cXQuvf6w\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"zq2yj\",\"use\":\"sig\",\"n\":\"qqqF-eYSGLzU_ieAreTx" +
      "a3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5w" +
      "fE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_" +
      "MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\",\"" +
      "e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"zq2yi\",\"use\":\"sig\",\"x\":\"Aeu8Jbm9XTwhwHcq19BthU6VIz4HU7qDG7CNa" +
      "e81RujWu3aSEWoX1aAVRh_ZMABfMKWCtXvhh2FEpSAcQRiKilfG\",\"y\":\"AOlx2rRLBLI3nh3eAlWI1ciFKWaw-6XEJw4o6nLXHRBVo92" +
      "ADYJBItvRdKcBk-BYb4Cewma7KtNuIK8zZ2HEen6d\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"zq2yh\",\"use\":\"si" +
      "g\",\"x\":\"gcqegh2wqsLgmikkGF1137rVf5QPhJb0hF7zwWNwSM5jyWwfwTlhNMc4V8FO01Jt\",\"y\":\"-bO4V5xtasOgWsrCGs_byd" +
      "qT0o3O29cA-5Sl7aqSfB7Z5-N3Dki5Ed2RZEU0Q7g0\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"zq2yg\",\"use\":\"s" +
      "ig\",\"x\":\"6elUcv15VpXlU995KVHZ3Jx6V8Cq7rCoodyIaXbQxS8\",\"y\":\"mHnmwkt-jhxWKjzx75egxVx2B25QiRzi5l0jNDF9hu" +
      "8\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"zq2yf\",\"use\":\"sig\",\"n\":\"wbcVJs-T_yP6TEWmdAqTo3qFsdt" +
      "pffUEqVbxtaWr-PiXs4DTWtig6kYO1Hwim0j780f6pBgWTKAOBhGm4e3RQH86cGA-kC6uD1931OLM1tcRhoaEsz9jrGWn31dSLBX9H_4YqR-a" +
      "1V3fov09BmfODE7MRVEqmZXHRxGUxXLGZn294LxZDRGEKwflTo3QZDG-Yirzf4UnbPERmSJsz6KE5FkO1k1YWCh1JnPlE9suQZC6OXIFRYwVH" +
      "UP_xo5vRxQ0tTO0z1YHfjNNpycLlCNOoxbuN3f7_vUD08U2v5YnXs8DPGCO_nG0gXDzeioqVDa2cvDKhOtSugbI_nVtPZgWSQ\",\"e\":\"A" +
      "QAB\"},{\"kty\":\"EC\",\"kid\":\"zq2ye\",\"use\":\"sig\",\"x\":\"AeRkafLScUO4UclozSPJpxJDknmB_SM70lA4MLGY9AGw" +
      "HIu1tTl-x9WjttYZNrQ6eE0bAWGb_0jgVccvz0SD7es-\",\"y\":\"AdIP5LQzH3oNFTZGO-CVnkvD35F3Cd611zYjts5frAeqlxVbB_l8Ud" +
      "iLFqIJVuVLoi-kFJ9htMBIo1b2-dKdhI5T\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"zq2yd\",\"use\":\"sig\",\"x" +
      "\":\"cLP7G_dHWU7CGlB3h2Rt-yr4cuT2-ybk6Aq5zoBmzUo5jNrQR_IvrllfvdVfF1ub\",\"y\":\"-OzAuuaPViw3my3UAE3WiXOYlaa5M" +
      "Yz7dbMBSZjZhretKm118itVnCI_WRAkWMa7\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"zq2yc\",\"use\":\"sig\",\"" +
      "x\":\"IUk0VFdRVnVVmdCfZxREU0pXmUk9fub4JVnqVZ5DTmI\",\"y\":\"DNr82q7z1vfvIjp5a73t1yKg2vhcUDKqdsKh_FFbBZs\",\"c" +
      "rv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"zq2yb\",\"use\":\"sig\",\"n\":\"lMRL3ng10Ahvh2ILcpEiKNi31ykHP8Iq7A" +
      "ENbwvsUzfag4ZBtid6RFBsfBMRrS_dGx1Ajjkpgj3igGlKiu0ZsSeu3zDK2e4apJGonxOQr7W2Bpv0bltU3bVRUb6i3-jv5sok33l2lKD6q7_" +
      "UYRCmuo1ui2FGpwhorNVRFMe24HE895lvzGqDXUzsDKtMmZIt6Cj1WfJ68ZQ0gNByg-GVRtZ_BgZmyQwfTmPYxN_0uQ8usHz6kuSEysarzW_m" +
      "UX1VEdzJ2dKBxmNwQlTW9v1UDvhUd2VXbGk1BvbJzFYL7z6GbxwhCynN-1bNb2rCFtRSI3UB2MgPbRkyjS97B7j34w\",\"e\":\"AQAB\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("zq2yb"))), "", empty)))
        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          keyID = Some(KeyId("zq2yf"))), "", empty)))
        // a kid that's not in there
        keys3 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("nope"))), "", empty)))
        // a kid that is in there but for the wrong key type
        keys4 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("zq2yg"))), "", empty)))
        keys5 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES512),
          keyID = Some(KeyId("zq2yi"))), "", empty)))
        keys6 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES384),
          keyID = Some(KeyId("zq2yh"))), "", empty)))
        // real kid, wrong key type
        keys7 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES256),
          keyID = Some(KeyId("zq2yj"))), "", empty)))
        // what would likely be the next kid
        keys8 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES256),
          keyID = Some(KeyId("zq2y0"))), "", empty)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("zq2yb")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("zq2yf")) &&
          keys3.isEmpty && keys4.isEmpty &&
          keys5.length == 1 && keys5.head.keyID.contains(KeyId("zq2yi")) &&
          keys6.length == 1 && keys6.head.keyID.contains(KeyId("zq2yh")) &&
          keys7.isEmpty && keys8.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests googles jwks end point" in {
    // JSON content from https://www.googleapis.com/oauth2/v2/certs on Jan 7, 2015
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"da522f3b66777ff6af63460d2b54" +
      "9ad43b6660d6\",\"n\":\"69Eh051UHkBJx55OkavsrpeeulxaHzxC9pMjVNQnjhY5pwJ0YjB_FgJwOdFHEdPOc8uzi_Pnfr0ov0mE4cRTjn" +
      "EsSF9_sB0sJaLE-W5e54-UxwgEPNWd4qT-sYdBl5LOwRoCth9gJ_6YA0zCr0V3AmAwoPnYRC9xo0R5aZY4Xvk=\",\"e\":\"AQAB\"},{\"k" +
      "ty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"3b2b4413738f55cb2405ee30334082be07e0fcc0\",\"n\":\"8" +
      "A6XgAQoenKyOJCz6AA-YZ3oN1GTEr3TVvJLV5ZoFdmPNvUohB2RXEJ4jRY16_z2SUK40ZPl_XPCAjl7vzf0BznUJYV33JwZFmCYoSWofllQUQ" +
      "u2iaJjyuQG7_PSYhBO5XxfTcIZGL6n4_87vp9jIFdm5J9bZgvwUgI5q7iooJs=\",\"e\":\"AQAB\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("da522f3b66777ff6af63460d2b549ad43b6660d6"))), "", empty)))

        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("3b2b4413738f55cb2405ee30334082be07e0fcc0"))), "", empty)))
        // a kid that's not in there
        keys3 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("nope"))), "", empty)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("da522f3b66777ff6af63460d2b549ad43b6660d6")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("3b2b4413738f55cb2405ee30334082be07e0fcc0")) &&
          keys3.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests salesforce jwks end point" in {
    // JSON content from https://login.salesforce.com/id/keys on Jan 7, 2015
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"wIQtK09qsu1qCCQu1mHh6d_EyyOlbqMCV8WMacOyhZng1sbaFJY-0PIH46Kw1uhj" +
      "bHg94_r2UELYd30vF8xwViGhCmpPuSGhkxNoT5CMoJPS6JW-zBpR7suHqBUnaGdZ6G2uYZDpwWYs_4SJDuWzxVBrQqIM_ZVgUqutniQPmjMAX" +
      "5MqznBTnG3zm728BmNzS7T2gtzxs3jAgDsSAu3Kxp3D6NDGERhaAJ8jOgwHvmQK5xFi9Adw7sv2nCH-wM-C5fLJYmpGOSrTP1HLOlq--TROAv" +
      "WL9gcNEeq4arryIYux5syg66rHT8U2Uhb1PdXt7ReQY8wBnP2BBH1QH7rzOZ7UbqFLbQUQsZFAVMcfm7gJN8JWLlcSJZdC2zaY0wI5q8PWN-N" +
      "_GgAK64FKZQ7pB0bRQ5AQx-D3U4sYE4EcgSvV8fW86PaF1VXaHMFcom48gZ1GzE_V25uPb-0yue0cv9lejrIKDvRiJ5UiyUPphro4Aw2ZcDi_" +
      "8r8rqfglWhcnB4bGSri4kEBb_IdwvqKwRCqxlNdRnU1ooQeUBaVRwdbpj23Z1qtYjB55Wf2KOCJ6ewMyddq4bEAG6KIqPmssT7_exvygUyuW6" +
      "qhnCV-gTZEwFI0A6djsHM5itfkzNY47BeuAtGXjuaRnVYIEvTrnSj3Lx7YfvCIiGqFrG6y31Ak\",\"e\":\"AQAB\",\"alg\":\"RS256\"" +
      ",\"use\":\"sig\",\"kid\":\"188\"},{\"kty\":\"RSA\",\"n\":\"hsqiqMXZmxJHzWfZwbSffKfc9YYMxj83-aWhA91jtI8k-GMsEB" +
      "6mtoNWLP6vmz6x6BQ8Sn6kmn65n1IGCIlWxhPn9yqfXBDBaHFGYED9bBloSEMFnnS9-ACsWrHl5UtDQ3nh-VQTKg1LBmjJMmAOHdBLoUikfpx" +
      "8fjA1LfDn_1iNWnguj2ehgjWCuTn64UdUd84YNcfO8Ha0TAhWHOhkiluMyzGS0dtN0h8Ybyi5oL6Bf1sfhtOncUh1JuWMcmvICbGEkA_0vBbM" +
      "p9nCvXdMlpzMOCIoYYkQ-25SRZ0GpIr_oBIZByEm1XaJIqNXoC7qJ95iAyWkUiSegY_IcBV3nMXr-kDNn9Vm2cgLEJGymOiDQKH8g7VjraCIr" +
      "qWPD3DWv3Z6RsExs6i0gG3JU9cVVFwz87d05_yk3L5ubWb96uxsP9rkwZ3h8eJTfFrgMhk1ZwR-63Dk3ZLYisiAU0zKgr4vQ9qsCNPqDg0rke" +
      "qOY5k7Gy201_wh6Sw5dCNTTGmZZ1rNE-gyDu4-a1H40n8f2JFiH-xIOD9-w8HGYOu_oGlobK2KvzFYHTk-w7vtfhZ0j96UkjaBhVjYSMi4hf4" +
      "3xNbB4xJoHhHLESABLp9IYDlnzBeBXKumXDO5aRk3sFAEAWxj57Ec_DyK6UwXSR9Xqji5a1lEArUdFPYzVZ_YCec\",\"e\":\"AQAB\",\"a" +
      "lg\":\"RS256\",\"use\":\"sig\",\"kid\":\"194\"},{\"kty\":\"RSA\",\"n\":\"o8Fz0jXjZ0Rz5Kt2TmzP0xVokf-Q4Az-MQg5" +
      "i5MCxNNTQiZp7VkwAZeM0mJ-mKDbCzPm9ws43v8cxeiIkVZQqrAocnnb90MDCnU-7oD7MvOU4SbmhuLzVCyVZPIBRq5z0OgjcwLeD4trOoogk" +
      "LOu0kyuyzNoFkr712m_GZ1xic-X0MlFKq3-2cI4U2nEuuh-Xcy7bUqCx0zTJFPOOKghGYEZZ6biZ04VC-ERcW6cC19pEWm6vCqZJEsKPCfazV" +
      "AoHKZAukNd0XLPQd_W6xAaGnp8e7a5tFHn6dU6ikhI94ZieVp6WItWsQTDwJH-D7bVpVRG-lWL74lgcuQdFAtldm__k7FvlTXdqiLrd0rYuDn" +
      "TFiwUSsUXWBJbmGVsEOylZVPQAL-K7G7p3BRY4X26vOgfludwCOj7L7WFbd0IXziTm74xe2KZGKsFpoCjJI0z_D5Oe5bofswr1Ceafhl97suG" +
      "7OoInobt7QAQnnLcBVzUPz_TflOXDc5UiePptA0bxdd8MVENiDbTGGNz6DCzfL986QfcJLPB8aZa3lFN0kWPBkOclZagL4WpyIllB6euvZ2hf" +
      "pt8IY2_bmUN06luo6N7Fy0hSSFMWvfzaD8_Ff3czb1Kv-b0xI6Ugk4d67RNNSbTcRM2Muvx-dJgOyXqrc_hE96OOqcMjrGZJoXnCAM\",\"e" +
      "\":\"AQAB\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"190\"},{\"kty\":\"RSA\",\"n\":\"nOcQOvHV8rc-hcfP_RmxM" +
      "GjyVlruSLeFXTojYcbixaAH36scUejjaws31orUjmYqB5isE9ntdsL4DnsdP_MDJ2mtYD2FIh8tBkJjgXitjdcDclrwELAx846wBIlSES8wR6" +
      "czpdJZfSwhL_92EGpDH6z7lKEClqhDlbtZ-yFKFj9BQRwaEXWV7uuq23gxXOqyEN0WXl3ZJPgsodCnlXRn9y_r5CNV9V4wvzXGlJhT3Nv_N_Z" +
      "5XNZIjZnHdCuE_itT4a1xENEEds7Jjg5mRTlVFzYv5iQtBo7jdY5ogMTgKPmRh6hYuqLeki3AOAUff1AGaN9TZH60UxwTw03-DQJL5C2SuC_v" +
      "M5KIWxZxQniubfegUCBXpJSAJbLt8zSFztTcrLS4-wgUHo1A8TDNaO28_KsBUTWsrieOr3NfCn4bPNb7t8G90U60lW0GIhEda3fNYnV0WWpZV" +
      "O1jCRNy_JYUs3ECo0E1ZQJZD72Dm6UjiuH7eR3ZgNKR9tlLNdyZSpZUZPErLrXJ90d5XbmJYvRX9r93z6GQqOv5FQy1JhatwefxhKdyhkDEHs" +
      "qELO0XDqnDnmgxkEEU-lHYSVGz-iDlUZOUYTTCtxsPDmBIXOMuwp0UydJphO36qRQaDyEjHNsYKLj5KVvjDHS8Gw1FhbFvsoUrBHre4hLY9Pa" +
      "5meatV_k\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"192\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("188"))), "", empty)))

        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("194"))), "", empty)))
        keys3 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("190"))), "", empty)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("188")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("194")) &&
          keys3.length == 1 && keys3.head.keyID.contains(KeyId("190"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests Microsoft jwks end point" in {
    // JSON content from https://login.windows.net/common/discovery/keys on Jan 7, 2015
    // (n is base64 rather than base64url but we can still consume it http://www.ietf.org/mail-archive/web/jose/current/msg04807.html
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"kriMPdmBvx68skT8-mPAB3BseeA\",\"x5t\":\"kriMPd" +
      "mBvx68skT8-mPAB3BseeA\",\"n\":\"kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYV" +
      "JL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//C" +
      "fueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVE" +
      "i5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw==\",\"e\":\"AQAB\",\"x5c\":[\"MIIDPjCCAiqgAwIBAgIQsRiM0jheFZh" +
      "Kk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAw" +
      "WhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFA" +
      "AOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5" +
      "txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH" +
      "3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++" +
      "XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb" +
      "3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQ" +
      "HQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwN" +
      "fW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJ" +
      "X4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ\"]},{\"k" +
      "ty\":\"RSA\",\"use\":\"sig\",\"kid\":\"MnC_VZcATfM5pOYiJHMba9goEKY\",\"x5t\":\"MnC_VZcATfM5pOYiJHMba9goEKY\"," +
      "\"n\":\"vIqz+4+ER/vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq+RtwN1Vs/z57hO82kkzL+cQHZX3bMJD" +
      "+GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW/EW/P+C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5yCw5T/Vuwqqsio3V8wooWGMpp" +
      "61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp/KAS/qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3+T+IAbsk1wRtWDndhO6s1Os+" +
      "dck5TzyZ/dNOhfXgelixLUQ==\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0" +
      "BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAw" +
      "MFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBA" +
      "LyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilw" +
      "hF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYT" +
      "fGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88m" +
      "f3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZ" +
      "xFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEkt" +
      "KybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO" +
      "9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\"]}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("kriMPdmBvx68skT8-mPAB3BseeA"))), "", empty)))
        // check some x5x stuff here too 'cause MS includes x5t and x5c
        calculatedX5tOption1 <- EitherT(keys1.head.calculateX509CertificateSHA1Thumbprint[IO]())
        calculatedX5t1 <- calculatedX5tOption1.toRight(OptionEmpty.label("calculatedX5t1")).eLiftET[IO]
        expectedX5t1 <- Base64UrlNoPad.fromString("kriMPdmBvx68skT8-mPAB3BseeA").eLiftET[IO]
        _ <- isTrue(calculatedX5t1 === expectedX5t1, ThumbprintMismatch(`SHA-1`, expectedX5t1, calculatedX5tOption1))
          .eLiftET[IO]
        _ <- EitherT(keys1.head.checkX509CertificateSHA1Thumbprint[IO]())

        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("MnC_VZcATfM5pOYiJHMba9goEKY"))), "", empty)))
        calculatedX5tOption2 <- EitherT(keys2.head.calculateX509CertificateSHA1Thumbprint[IO]())
        calculatedX5t2 <- calculatedX5tOption2.toRight(OptionEmpty.label("calculatedX5t2")).eLiftET[IO]
        expectedX5t2 <- Base64UrlNoPad.fromString("MnC_VZcATfM5pOYiJHMba9goEKY").eLiftET[IO]
        _ <- isTrue(calculatedX5t2 === expectedX5t2, ThumbprintMismatch(`SHA-1`, expectedX5t2, calculatedX5tOption2))
          .eLiftET[IO]
        _ <- EitherT(keys2.head.checkX509CertificateSHA1Thumbprint[IO]())

        keys3 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          x509CertificateSHA1Thumbprint = Some(expectedX5t2)), "", empty)))
        calculatedX5tOption3 <- EitherT(keys3.head.calculateX509CertificateSHA1Thumbprint[IO]())
        calculatedX5t3 <- calculatedX5tOption3.toRight(OptionEmpty.label("calculatedX5t3")).eLiftET[IO]
        _ <- isTrue(calculatedX5t3 === expectedX5t2, ThumbprintMismatch(`SHA-1`, expectedX5t2, calculatedX5tOption3))
          .eLiftET[IO]
        _ <- EitherT(keys3.head.checkX509CertificateSHA1Thumbprint[IO]())

        keys4 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          x509CertificateSHA1Thumbprint = Some(expectedX5t1)), "", empty)))
        calculatedX5tOption4 <- EitherT(keys4.head.calculateX509CertificateSHA1Thumbprint[IO]())
        calculatedX5t4 <- calculatedX5tOption4.toRight(OptionEmpty.label("calculatedX5t4")).eLiftET[IO]
        _ <- isTrue(calculatedX5t4 === expectedX5t1, ThumbprintMismatch(`SHA-1`, expectedX5t1, calculatedX5tOption4))
          .eLiftET[IO]
        _ <- EitherT(keys4.head.checkX509CertificateSHA1Thumbprint[IO]())

      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("kriMPdmBvx68skT8-mPAB3BseeA")) &&
          keys1.head.x509CertificateSHA256Thumbprint.isEmpty && keys1.head.x509URL.isEmpty &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("MnC_VZcATfM5pOYiJHMba9goEKY")) &&
          keys2.head.x509CertificateSHA256Thumbprint.isEmpty && keys2.head.x509URL.isEmpty &&
          keys3.length == 1 && keys3.head.keyID.contains(KeyId("MnC_VZcATfM5pOYiJHMba9goEKY")) &&
          keys3.head.x509CertificateSHA256Thumbprint.isEmpty && keys3.head.x509URL.isEmpty &&
          keys4.length == 1 && keys4.head.keyID.contains(KeyId("kriMPdmBvx68skT8-mPAB3BseeA")) &&
          keys4.head.x509CertificateSHA256Thumbprint.isEmpty && keys4.head.x509URL.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests Gluu jwks end point" in {
    // JSON content from https://seed.gluu.org/oxauth/seam/resource/restv1/oxauth/jwks on Jan 7, 2015
    // the "alg":"EC" isn't right, IMHO but makes a nice test case I suppose   http://www.ietf.org/mail-archive/web/jose/current/msg04783.html
    // 我不同意。不规范都该死
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"AJYQhwMG7-PCPzmp" +
      "-E8_Jz8zGVuIA0upMUrqOLa9lpcduLXlpgv_g525DU8vJ34GqNgYcsjNw2dvV03cWSU8VguWSC5ijHfhzf3cSbEJTcBOfCpbir8hRgAOkU4gq" +
      "Sf8rXTugyJ6jw4wiMEnLlk8j18chGQvn-bqKDw9aEqg_ssxz3f0yO_p4bl5_9n5FGQHGyZYv6B_PsAHZkm_DNDu7Wa_vfv8vnq3u_38uf4WC6" +
      "S5cMR15B74Ja0ylR498h23E2riz9o7X2rLsL26JLUWSfjDw-twYqF4jt6oCGDIIv4zCYdpim-2L5qKMkASPAbWs_KfXIIhJuLohrpzOaqZh_k" +
      "\",\"e\":\"AQAB\",\"x5c\":[\"MIIDMDCCAhgCgYBDSFLKDmTPKXlpVPR8EuhbSUGCgd2okr\\/tL7sW9nlr6oKpNovrEFUL0YkqT59dNG" +
      "7zldXJWY92VQDJSmpeRX6TX74efV1prpF4Y9sW5y0iu9njcAxE2zDBCM6rGWNf+WWajOajuYkbqEfOOl1PikQkFCliIUdDYSvId6Sco05tsjA" +
      "NBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxMloXDTE0MDIxMTIxMjQxMlowHjEc" +
      "MBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJYQhwMG7+PCPzmp+E8\\/Jz8zGVu" +
      "IA0upMUrqOLa9lpcduLXlpgv\\/g525DU8vJ34GqNgYcsjNw2dvV03cWSU8VguWSC5ijHfhzf3cSbEJTcBOfCpbir8hRgAOkU4gqSf8rXTugy" +
      "J6jw4wiMEnLlk8j18chGQvn+bqKDw9aEqg\\/ssxz3f0yO\\/p4bl5\\/9n5FGQHGyZYv6B\\/PsAHZkm\\/DNDu7Wa\\/vfv8vnq3u\\/38u" +
      "f4WC6S5cMR15B74Ja0ylR498h23E2riz9o7X2rLsL26JLUWSfjDw+twYqF4jt6oCGDIIv4zCYdpim+2L5qKMkASPAbWs\\/KfXIIhJuLohrpz" +
      "OaqZh\\/kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAA1c5yds2m89XnhEr+WFE8APdkveJDxa+p7R5TSR924+nq4v11UPzSqkpn+Nk\\/QYM6" +
      "uUBH1Z0axBgrFy\\/auunXbtDfm\\/HzQkTx+Dlq4DgcTzUKUC\\/3ObfVQCEFCaKfbtg+PTM7QytJgeoGPbjWneIvgis3zvmCULknGt\\/7C" +
      "Yh2URAaBkWitLBuYa0yCnPSfajNpnMrOEPBElsU0lC+ka4N\\/C\\/v5nvkfnneMDnr8UMV2OkRv+BDyoUg5HWgtWNV7AE0I7I89aVmLxWGp0" +
      "tWwnZxbfbfGChGEhHHgx0eri9L4+Hd9l5ZP1csuojHoHHcMSmaT2\\/4edG4Eyxm6C2GPrCGg==\"]},{\"kty\":\"RSA\",\"kid\":\"2" +
      "\",\"use\":\"sig\",\"alg\":\"RS384\",\"n\":\"ALs6oVo2LGaBb39Z8loTmhiZhZPq0wbfTpvhFjFoEXJRTLlucPYftbV3g_aTmUiL" +
      "_Pz919nWCj-X2WOtE3g7du823qJqX8ieas_c7ehZcG8D-pxxUipRqBDX76Bw6jZ00QtEcc89MU4GJaROHcm0L8iQMkSZgIFN8u5_ZvtQzWyyn" +
      "XTmHve0nNMoVhTn1nrxK_dGotCDkzJZ3ph7Rjq5smxjoPGrzzeesCo9c_3edrD4jiFkDUlEOabvqfhTeX1K_X3HO-LHBBI2QxvP7U1MarxyP8" +
      "TMsIQjjR1ggGNkdv4gtTK5AixjHlQYswQragzBWQ5dTrUNl366NNpYTD3-o3M\",\"e\":\"AQAB\",\"x5c\":[\"MIIDMDCCAhgCgYBmLjh" +
      "1H5nHW466kS5EPsNmi+92mYsiRZ4Al+GOLr\\/067Dpy\\/qwiSHVcIsY0pPCORukIvwxf2CUHeKRg7HDD87jddENjlcEpUDNT9EjxixymSbr" +
      "QEerPliD69MCTqGp6KyfRrf44cuEQFDdSQbYW+b25Ivms33sLim+\\/5uENE7MbjANBgkqhkiG9w0BAQwFADAeMRwwGgYDVQQDExNUZXN0IEN" +
      "BIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxM1oXDTE0MDIxMTIxMjQxM1owHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCCASIw" +
      "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALs6oVo2LGaBb39Z8loTmhiZhZPq0wbfTpvhFjFoEXJRTLlucPYftbV3g\\/aTmUiL\\/Pz91" +
      "9nWCj+X2WOtE3g7du823qJqX8ieas\\/c7ehZcG8D+pxxUipRqBDX76Bw6jZ00QtEcc89MU4GJaROHcm0L8iQMkSZgIFN8u5\\/ZvtQzWyynX" +
      "TmHve0nNMoVhTn1nrxK\\/dGotCDkzJZ3ph7Rjq5smxjoPGrzzeesCo9c\\/3edrD4jiFkDUlEOabvqfhTeX1K\\/X3HO+LHBBI2QxvP7U1Ma" +
      "rxyP8TMsIQjjR1ggGNkdv4gtTK5AixjHlQYswQragzBWQ5dTrUNl366NNpYTD3+o3MCAwEAATANBgkqhkiG9w0BAQwFAAOCAQEAS7rNA06jrB" +
      "PCLMuUq38jlHolnPHQxS1Qg0aUUCNy955AMnoh4tF60ejIxIwiZIXZdWBR0cIDxV+8Cy3WYj4a8FDQnntVR0dREfGQyICf0v5reEenSj2u2DU" +
      "HgCpwFbpmrh9UTjg0swU9G06LV+q\\/arDq+ejK9Wty8fWBw7RSpx3s5nq7xuA+TY4wqGTtIdPAI1q4oWOHn0x65FV6Mwv3Lis8gSXIvBhzjk" +
      "AIh6PXK7YMic43sR6MGOKCJ3iO5bqW2kSJ0KQXOv6nxUwrs9k2dgrTxdUwNycZEYiQEiXK\\/sPHIhqEmRZK6H00dLz\\/99K4ZLm17YeF+7g" +
      "4Sk0ZkMarpw==\"]},{\"kty\":\"RSA\",\"kid\":\"3\",\"use\":\"sig\",\"alg\":\"RS512\",\"n\":\"AK3SFO9Q0jJP1-n2ys" +
      "7yyP70r149_EQ1z0EfgIg2qpAMXcuyDIWu-dqD05fkicN2izHAf463LydeRUXWAc058F-mYw8y69qcZyDxnqYu_IlmK77tDgE-oilPVF_JW3W" +
      "MXAl3MHvhAQwc-2q2lLbs3qa6BqpZgXofiJdURaRS990qO1fqYm1ihT8hmq8WQmXbDS_0-L4sP3O8cK9FXWhWqtfC1yo0Ziv8OSQ3h8dYRFAu" +
      "pqESRpe3EzV5DICdHAdBBrSkLyfPTLIzavfCkhI4zB6VrxLF4l1yTo7ucfnobIUaiNEvwVwkytLrNM4HPk4dO8H0woEomqj4QzIPkUGLxLc\"" +
      ",\"e\":\"AQAB\",\"x5c\":[\"MIIDMDCCAhgCgYA6qJ8lNNfbB0VhX2UZLXLizoC1BCPEc2W25\\/hJKay\\/GXVMIA+42AvUqWSonkwDAL" +
      "udfWbPVR3vOqB8iq4O75aaGiEAw6roiOHHRVTCZm1PCH+TlGh+jATybe83cBtCGTmvt81Or4q0NK\\/sJ3hi3e\\/ds4IPn3eWScd1lhVUzIj" +
      "2uDANBgkqhkiG9w0BAQ0FADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxM1oXDTE0MDIxMTIxMjQxM1ow" +
      "HjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK3SFO9Q0jJP1+n2ys7yyP70r" +
      "149\\/EQ1z0EfgIg2qpAMXcuyDIWu+dqD05fkicN2izHAf463LydeRUXWAc058F+mYw8y69qcZyDxnqYu\\/IlmK77tDgE+oilPVF\\/JW3WM" +
      "XAl3MHvhAQwc+2q2lLbs3qa6BqpZgXofiJdURaRS990qO1fqYm1ihT8hmq8WQmXbDS\\/0+L4sP3O8cK9FXWhWqtfC1yo0Ziv8OSQ3h8dYRFA" +
      "upqESRpe3EzV5DICdHAdBBrSkLyfPTLIzavfCkhI4zB6VrxLF4l1yTo7ucfnobIUaiNEvwVwkytLrNM4HPk4dO8H0woEomqj4QzIPkUGLxLcC" +
      "AwEAATANBgkqhkiG9w0BAQ0FAAOCAQEASyqKmhz7o5VjB5gKSBaLw9yqNo8zruYizkLKhUxzAdna6qz73ONAdXtrdok79Qpio2nlvyPgspF9r" +
      "YKgwxguvHpTOkdCZ3LNPF4QLsn3I0vs3gr8+oXhXbA58kqsBSAyt54HDTa7Zh8c\\/G1u5W\\/0+lsgCwtMSzeISnNrqY3a3K97Uy6OoxDqWk" +
      "8t4W1OgtYhi6wiq7BGQ9xg7QlwMrVNc165ixgaW46\\/tpafONG7+WFaWnzROPHrh6rSv4diz8bd7MqDDVLB2q\\/QolzWTtxHSgkFu1t5dNE" +
      "QznJI5Ay\\/txPKgRNiv3EhD8fv9EKsip1epKtsP5Il6mLktPBjZMHjMg==\"]},{\"kty\":\"EC\",\"kid\":\"4\",\"use\":\"sig\"" +
      ",\"alg\":\"EC\",\"crv\":\"P-256\",\"x\":\"eZXWiRe0I3TvHPXiGnvO944gjF1o4UmitH2CVwYIrPg\",\"y\":\"AKFNss7S35tOs" +
      "p5iY7-YuLGs2cLrTKFk80JvgVzMPHQ3\",\"x5c\":[\"MIIBpDCCAUoCgYBCs6x21IvwVHFgJxiRegyHdSiEHFur9Wj2qM5oNkv6sFbbC75L" +
      "849qCgMEzdtqIhCiCnFg6PaQdswHkcclXix+y0sycyIM6l429faY3jz5eQs5SYwXYkENStzTZBsWK6u7bPiV3HvjnIv+r1af8nvO5F0tiH0TC" +
      "+auDj9FgRmYljAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxMVoXDTE0MDIxMTIxMj" +
      "QxMVowHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHmV1okXtCN07xz14hp7zveOIIx" +
      "daOFJorR9glcGCKz4oU2yztLfm06ynmJjv5i4sazZwutMoWTzQm+BXMw8dDcwCgYIKoZIzj0EAwIDSAAwRQIhAI4aRAoTVm3was6UimA1lFL2" +
      "RId+t\\/fExaviosXNKg\\/IAiBpZB4XXcnQISwauSJ1hXNnSEcONXdqvO5gDHu+X7QHLg==\"]},{\"kty\":\"EC\",\"kid\":\"5\",\"" +
      "use\":\"sig\",\"alg\":\"EC\",\"crv\":\"P-384\",\"x\":\"XGp9ovRmtaBjlZKGI1XDBUB6F3d4Xov4JFKUCaeVjMD0_GAp20IB_w" +
      "Zz6howe3yi\",\"y\":\"Vhy6zh3KOkDqSA5WP6BtDyS9CZR7RoCCWfwymBB3HIBIR_yl32hnSYXtlwEr2EoK\",\"x5c\":[\"MIIB4zCCAW" +
      "gCgYEA9v7jYfmKYNePYWQt6M8BQsvb4swqpVEYulCJq8bOKuhz5\\/VgM8J8lGaClDRhY6msrtW16kRbZvnMvgKNBJ52TXGKtEFylMzDQ4k\\" +
      "/HYGb1w7FwlXVyv3TScFNm9JnfsMe7ecOcanRFn+hYjiZdEcTB85wLvpKRDlkpuIf0khB8iMwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAxMTVGVz" +
      "dCBDQSBDZXJ0aWZpY2F0ZTAeFw0xMzAyMTEyMTI0MTFaFw0xNDAyMTEyMTI0MTFaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwd" +
      "jAQBgcqhkjOPQIBBgUrgQQAIgNiAARcan2i9Ga1oGOVkoYjVcMFQHoXd3hei\\/gkUpQJp5WMwPT8YCnbQgH\\/BnPqGjB7fKJWHLrOHco6QO" +
      "pIDlY\\/oG0PJL0JlHtGgIJZ\\/DKYEHccgEhH\\/KXfaGdJhe2XASvYSgowCgYIKoZIzj0EAwIDaQAwZgIxAOV6rC\\/muVarcSXaP9Z7Pn7" +
      "aI3o5fixoVx6E\\/xYTOg+H10FMsluIdahjt90fNJYiYAIxAO+IHenKHe2xr8RpphzqWnAexswcEI6A3drp1f24Z8XtTJHNIHAVP6wr88oz5+" +
      "eFoQ==\"]},{\"kty\":\"EC\",\"kid\":\"6\",\"use\":\"sig\",\"alg\":\"EC\",\"crv\":\"P-521\",\"x\":\"KrVaPTvvYmU" +
      "USf_1UpwJt_Lg9UT-8OHD_AUd-d7-Q8Rfs4t-lTJ5KEyjbfMzTHsvNulWftuaMH6Ap3l5vbDb2nQ\",\"y\":\"AIxSEGvlKlWZiN_Rc3VjBs" +
      "5oVB5l-JfCZHm2LyZpOxAzWrpjHlK121H2ZngM8Ra8ggKa64hEMDE1fMV__C_EZv9m\",\"x5c\":[\"MIICLDCCAY0CgYAcLY90WqvtOS1H1" +
      "zyF0jrrHT549yccB4rk61J96JlOnRTbuTq7wWWgOm6csS+19GMRIIDk5njc6M50WUeCcFEURy9wmZKAW3\\/PgOgnPydjnvBIIofOfZOVeaLj" +
      "ji64h7Ju\\/Ur8Ki28sN5xeyz5iGhqst1CJ0RVBAbpT4IN2szemTAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXR" +
      "lMB4XDTEzMDIxMTIxMjQxMVoXDTE0MDIxMTIxMjQxMVowHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCBmzAQBgcqhkjOPQIBBgUr" +
      "gQQAIwOBhgAEACq1Wj0772JlFEn\\/9VKcCbfy4PVE\\/vDhw\\/wFHfne\\/kPEX7OLfpUyeShMo23zM0x7LzbpVn7bmjB+gKd5eb2w29p0A" +
      "IxSEGvlKlWZiN\\/Rc3VjBs5oVB5l+JfCZHm2LyZpOxAzWrpjHlK121H2ZngM8Ra8ggKa64hEMDE1fMV\\/\\/C\\/EZv9mMAoGCCqGSM49BA" +
      "MCA4GMADCBiAJCAb+BYADga2su9Sejzgbfz4lrSPt1l7PWeyDXtTGqa8yvIf4f3Hudp272WeXxeBpL\\/7EFtho8CvG8zhvrp7bC+E84AkIBv" +
      "3V6seORxzsO5hv1mtAKIPdFmePIrKrGFqa7ESR56DZxVYeJ5GHi1gU4LJdGcUYDpz0GDqznxAmvA3AimrwAWUk=\"]}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("1"))), "", empty)))
        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS384),
          keyID = Some(KeyId("2"))), "", empty)))
        keys3 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          keyID = Some(KeyId("3"))), "", empty)))
        keys4 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES256),
          keyID = Some(KeyId("4"))), "", empty)))
        keys5 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES384),
          keyID = Some(KeyId("5"))), "", empty)))
        keys6 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES512),
          keyID = Some(KeyId("6"))), "", empty)))
        x5tS2567 <- Base64UrlNoPad.fromString("Xm5kcmgZp3dZmZc_-K31CzStJl5pH3QjRp45D8uhinM")
          .eLiftET[IO]

        keys7 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          x509CertificateSHA256Thumbprint = Some(x5tS2567)), "", empty)))

        three <- jwks.keys.find(_.keyID.contains(KeyId("3"))).toRight(OptionEmpty.label("three")).eLiftET[IO]
        three <- typed[AsymmetricJsonWebKey](three).eLiftET[IO]
        threeLeafCertificate <- EitherT(three.getLeafCertificate[IO]())
        threeLeafCertificate <- threeLeafCertificate.toRight(OptionEmpty.label("leafCertificate")).eLiftET[IO]
        threeX5t <- EitherT(threeLeafCertificate.base64UrlThumbprint[IO](`SHA-1`))
        threeX5tS256 <- EitherT(threeLeafCertificate.base64UrlThumbprint[IO](`SHA-256`))

        keys8 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          x509CertificateSHA256Thumbprint = Some(threeX5tS256)), "", empty)))
        keys9 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          x509CertificateSHA1Thumbprint = Some(threeX5t)), "", empty)))
        x5tS25610 <- Base64UrlNoPad.fromString("NOPENOPE3dZmZc_-K31CzStJl5pH3QjRp45D8uhinM").eLiftET[IO]
        keys10 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          x509CertificateSHA256Thumbprint = Some(x5tS25610)), "", empty)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("1")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("2")) &&
          keys3.length == 1 && keys3.head.keyID.contains(KeyId("3")) &&
          keys4.isEmpty && keys5.isEmpty && keys6.isEmpty &&
          keys7.length == 1 && keys7.head.keyID.contains(KeyId("3")) &&
          keys8.length == 1 && keys8.head.keyID.contains(KeyId("3")) &&
          keys9.length == 1 && keys9.head.keyID.contains(KeyId("3")) &&
          keys10.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests forgerock jwks end point" in {
    // JSON content from https://demo.forgerock.com:8443/openam/oauth2/connect/jwk_uri on Jan 8, 2015
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"fb301b61-9b8a-4c34-9212-5d6fb9df1a57\",\"use\":\"sig\",\"alg\"" +
      ":\"RS256\",\"n\":\"AK0kHP1O-RgdgLSoWxkuaYoi5Jic6hLKeuKw8WzCfsQ68ntBDf6tVOTn_kZA7Gjf4oJAL1dXLlxIEy-kZWnxT3FF-0" +
      "MQ4WQYbGBfaW8LTM4uAOLLvYZ8SIVEXmxhJsSlvaiTWCbNFaOfiII8bhFp4551YB07NfpquUGEwOxOmci_\",\"e\":\"AQAB\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("fb301b61-9b8a-4c34-9212-5d6fb9df1a57"))), "", empty)))
      yield
        keys.length == 1 && keys.head.keyID.contains(KeyId("fb301b61-9b8a-4c34-9212-5d6fb9df1a57"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests miter jwks end point" in {
    // JSON content from https://mitreid.org/jwk on Jan 8, 2015
    val json = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"n\":\"23zs5r8PQKpsKeoUd2Bjz3TJkUljWqMD8X98SaIb1LE7dCQ" +
      "zi9jwO58FGL0ieY1Dfnr9-g1iiY8sNzV-byawK98W9yFiopaghfoKtxXgUD8pi0fLPeWmAkntjn28Z_WZvvA265ELbBhphPXEJcFhdzUfgESH" +
      "VuqFMEqp1pB-CP0\",\"kty\":\"RSA\",\"kid\":\"rsa1\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("rsa1"))), "", empty)))
      yield
        keys.length == 1 && keys.head.keyID.contains(KeyId("rsa1"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid tests Nri Php jwks end point" in {
    // JSON content from https://connect.openid4.us/connect4us.jwk on Jan 8, 2015
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"tf_sB4M0sHearRLzz1q1JRgRdRnwk0lz-IcVDFlpp2dtDVyA-ZM8Tu1swp7upaTN" +
      "ykf7cp3Ne_6uW3JiKvRMDdNdvHWCzDHmbmZWGdnFF9Ve-D1cUxj4ETVpUM7AIXWbGs34fUNYl3Xzc4baSyvYbc3h6iz8AIdb_1bQLxJsHBi-y" +
      "dg3NMJItgQJqBiwCmQYCOnJlekR-Ga2a5XlIx46Wsj3Pz0t0dzM8gVSU9fU3QrKKzDFCoFHTgig1YZNNW5W2H6QwANL5h-nbgre5sWmDmdnfi" +
      "U6Pj5GOQDmp__rweinph8OAFNF6jVqrRZ3QJEmMnO42naWOsxV2FAUXafksQ\",\"e\":\"AQAB\",\"kid\":\"ABOP-00\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS384),
          keyID = Some(KeyId("ABOP-00"))), "", empty)))
      yield
        keys.length == 1 && keys.head.keyID.contains(KeyId("ABOP-00"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with no kid test nov jwks end point" in {
    // JSON content from https://connect-op.herokuapp.com/jwks.json on Jan 8, 2015
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n-99qTXu5yNa30" +
      "MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE-Yopfu3B58QlgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf-PCi" +
      "SQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JBqaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ-INLY6jnKG_RpsvyvGNnwP" +
      "9pMvcP1phKsWZ10ofuuhJGRp8IxQL9RfzT87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw\",\"use\":\"sig\"}]}"
    val cs = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2Nvbm5lY3Qtb3AuaGVyb2t1YXBwLmNvbSIsInN1YiI6I" +
      "jZiOTYyYzk1Nzk4NThkNzJjNjY0M2FiZjhkN2E2ZWJjIiwiYXVkIjoiZGIwZTdmYTNmNmQwN2ZhMjYzMjZhNzE4NjQwMGVhOTEiLCJleHAiOj" +
      "E0MjA3NTI0NzAsImlhdCI6MTQyMDczMDg3MCwibm9uY2UiOiJiOGU1OTlhM2JkYTRkNDExYzhiMDc0OGM1MGQwZjQxNyJ9.FNyq7K90vW7eLm" +
      "sjzUPQ8eTnTreOWXVt_WKyqS686_D_kZ9tl3_uE3tKBw004XyFwMYd-4zWhvXaDPkhFGJ6BPy_woxnQdiTobNE-jyQscp6-6keg3QRkjV-Te7" +
      "F48Pyfzl-lwvzhb76ygjuv7v_1Nf49fHZb-SiQ2KmapabHpIfVvuqTQ_MZjU613XJIW0tMqFv4__fgaZD-JU6qCkVbkXpvIMg_tZDafsipJ6Z" +
      "YH9_9JuXQqjzmsM6vHN53MiQZaDtwb6nLDFln6YPqmVPXJV6SLvM_vn0g5w6jvmfsPGZL-xo-iqWbYtnMK-dX4HmnLpK4JVba_OnA9NQfj2DRQ"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        jws <- JsonWebSignature.parse(cs).eLiftET[IO]
        keys <- EitherT(jwks.verificationPrimitives[IO](jws))
        _ <- EitherT(jws.check[IO](keys.head.key, keys.head.configuration))
      yield
        keys.length == 1
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with no kid test ryo tio jwks end point" in {
    // JSON content from https://openidconnect.info/jwk/jwk.json on Jan 8, 2015
    // missing kty and misused alg, user should be use
    val json = "{\"keys\":[{\"alg\":\"RSA\",\"mod\":\"4ZLcBYTH4S3b80iEkDKTAmLvNM3XkqgdQoLPtNgNoilmHD1wian5_EDl2IvwAJ" +
      "Rug9I0TnhVuMZW3ylhsPxus3Iu70nCQbOdsoBCobNzm6RaLUsz6LjRa2mvLMHeG1CP5rGWiv5GwBU8DNuUf_uPWXMe9K3i3E27nm4NnwDcOMP" +
      "ETpr6PLB2h4iXsHrKGLIFPdoPx_TIcrbj7RR9vWtrkj1pHt2OnJy5cFmXXRc77SZw0qRouVD0cqiS0XPHTaoFgmFr1x7NdbENxMJZJ-VPaIqN" +
      "0ht2tFX5oOCClhNjBTKc2U-c-b32ETtUnNUu1kHafS-V0qsobmy-Cq_gyyQY2w\",\"exp\":\"AQAB\",\"user\":\"sig\"}]}"
    IO.unit.asserting(_ => assert(decode[Id, JsonWebKeySet](json).map(_.keys.isEmpty).getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with unique kid and x5t test thinktecture jwks end point" in {
    // JSON content from https://identity.thinktecture.com/.well-known/jwks on Jan 8, 2015
    //  n is regular base64 rather than base64url http://www.ietf.org/mail-archive/web/jose/current/msg04783.html
    val json = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"a3rMUgMFv9tPclLa6yF3zAkfquE\",\"x5t\":\"a3rMUg" +
      "MFv9tPclLa6yF3zAkfquE\",\"e\":\"AQAB\",\"n\":\"qnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynq" +
      "Y5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5" +
      "YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8H" +
      "N7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFw==\",\"x5c\":[\"MIIDBTCCAfGgAwIBAgIQNQb+T2ncIrN" +
      "A6cKvUA1GWTAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjIwMDAwWhcNMjAwMTIwMjIwMDAwWjAVMRMwEQYDVQQD" +
      "EwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAW" +
      "Twsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8S" +
      "n9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStb" +
      "NAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFwIDAQABo1wwWjATBgNVHSUEDDAKBggrBgEF" +
      "BQcDATBDBgNVHQEEPDA6gBDSFgDaV+Q2d2191r6A38tBoRQwEjEQMA4GA1UEAxMHRGV2Um9vdIIQLFk7exPNg41NRNaeNu0I9jAJBgUrDgMCH" +
      "QUAA4IBAQBUnMSZxY5xosMEW6Mz4WEAjNoNv2QvqNmk23RMZGMgr516ROeWS5D3RlTNyU8FkstNCC4maDM3E0Bi4bbzW3AwrpbluqtcyMN3Pi" +
      "vqdxx+zKWKiORJqqLIvN8CT1fVPxxXb/e9GOdaR8eXSmB0PgNUhM4IjgNkwBbvWC9F/lzvwjlQgciR7d4GfXPYsE1vf8tmdQaY8/PtdAkExmb" +
      "rb9MihdggSoGXlELrPA91Yce+fiRcKY3rQlNWVd4DOoJ/cPXsXwry8pWjNCo5JD8Q+RQ5yZEy7YPoifwemLhTdsBz3hlZr28oCGJ3kbnpW0xG" +
      "vQb3VHSTVVbeei0CfXoW6iz1\"]}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("a3rMUgMFv9tPclLa6yF3zAkfquE"))), "", empty)))
        x5t <- Base64UrlNoPad.fromString("a3rMUgMFv9tPclLa6yF3zAkfquE").eLiftET[IO]
        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          x509CertificateSHA1Thumbprint = Some(x5t)), "", empty)))
        actualX5t <- keys2.head.x509CertificateSHA1Thumbprint.toRight(OptionEmpty.label("actualX5t")).eLiftET[IO]
        _ <- isTrue(actualX5t === x5t, ThumbprintMismatch(`SHA-1`, x5t, Some(actualX5t))).eLiftET[IO]
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("a3rMUgMFv9tPclLa6yF3zAkfquE")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("a3rMUgMFv9tPclLa6yF3zAkfquE"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with not unique kids so disambiguate by alg use kty tests" in {
    // JSON content from a PingFederate JWKS endpoint modified by hand to fake up some semi-plausible cases (same kid used for different key types and algs)
    val json = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"3\",\"use\":\"sig\",\"x\":\"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9o" +
      "u3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\",\"y\":\"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrv" +
      "P2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\",\"crv\":\"P-521\",\"alg\":\"ES521\"},{\"kty\":\"EC\",\"kid\":\"" +
      "3\",\"use\":\"sig\",\"x\":\"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\",\"y\":\"Bt0Hwj" +
      "lM4RoyCfq7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\",\"crv\":\"P-384\",\"alg\":\"ES384\"},{\"kty\":\"" +
      "EC\",\"kid\":\"3\",\"use\":\"sig\",\"x\":\"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\",\"y\":\"ZlAzvRY_PP0l" +
      "TJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\",\"crv\":\"P-256\",\"alg\":\"ES256\"},{\"kty\":\"RSA\",\"kid\":\"3\",\"use\"" +
      ":\"sig\",\"n\":\"qqqF-eYSGLzU_ieAreTxa3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBn" +
      "L20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5wfE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5" +
      "oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup" +
      "48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"2\",\"use\":\"sig\",\"x\":\"Aeu8" +
      "Jbm9XTwhwHcq19BthU6VIz4HU7qDG7CNae81RujWu3aSEWoX1aAVRh_ZMABfMKWCtXvhh2FEpSAcQRiKilfG\",\"y\":\"AOlx2rRLBLI3nh" +
      "3eAlWI1ciFKWaw-6XEJw4o6nLXHRBVo92ADYJBItvRdKcBk-BYb4Cewma7KtNuIK8zZ2HEen6d\",\"crv\":\"P-521\",\"alg\":\"ES52" +
      "1\"},{\"kty\":\"EC\",\"kid\":\"2\",\"use\":\"sig\",\"x\":\"gcqegh2wqsLgmikkGF1137rVf5QPhJb0hF7zwWNwSM5jyWwfwT" +
      "lhNMc4V8FO01Jt\",\"y\":\"-bO4V5xtasOgWsrCGs_bydqT0o3O29cA-5Sl7aqSfB7Z5-N3Dki5Ed2RZEU0Q7g0\",\"crv\":\"P-384\"" +
      ",\"alg\":\"ES384\"},{\"kty\":\"EC\",\"kid\":\"2\",\"use\":\"sig\",\"x\":\"6elUcv15VpXlU995KVHZ3Jx6V8Cq7rCoody" +
      "IaXbQxS8\",\"y\":\"mHnmwkt-jhxWKjzx75egxVx2B25QiRzi5l0jNDF9hu8\",\"crv\":\"P-256\",\"alg\":\"ES256\"},{\"kty" +
      "\":\"RSA\",\"kid\":\"2\",\"use\":\"sig\",\"n\":\"wbcVJs-T_yP6TEWmdAqTo3qFsdtpffUEqVbxtaWr-PiXs4DTWtig6kYO1Hwi" +
      "m0j780f6pBgWTKAOBhGm4e3RQH86cGA-kC6uD1931OLM1tcRhoaEsz9jrGWn31dSLBX9H_4YqR-a1V3fov09BmfODE7MRVEqmZXHRxGUxXLGZ" +
      "n294LxZDRGEKwflTo3QZDG-Yirzf4UnbPERmSJsz6KE5FkO1k1YWCh1JnPlE9suQZC6OXIFRYwVHUP_xo5vRxQ0tTO0z1YHfjNNpycLlCNOox" +
      "buN3f7_vUD08U2v5YnXs8DPGCO_nG0gXDzeioqVDa2cvDKhOtSugbI_nVtPZgWSQ\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"" +
      "1\",\"use\":\"sig\",\"x\":\"AeRkafLScUO4UclozSPJpxJDknmB_SM70lA4MLGY9AGwHIu1tTl-x9WjttYZNrQ6eE0bAWGb_0jgVccvz" +
      "0SD7es-\",\"y\":\"AdIP5LQzH3oNFTZGO-CVnkvD35F3Cd611zYjts5frAeqlxVbB_l8UdiLFqIJVuVLoi-kFJ9htMBIo1b2-dKdhI5T\"," +
      "\"crv\":\"P-521\",\"alg\":\"ES521\"},{\"kty\":\"EC\",\"kid\":\"1\",\"use\":\"sig\",\"x\":\"cLP7G_dHWU7CGlB3h2" +
      "Rt-yr4cuT2-ybk6Aq5zoBmzUo5jNrQR_IvrllfvdVfF1ub\",\"y\":\"-OzAuuaPViw3my3UAE3WiXOYlaa5MYz7dbMBSZjZhretKm118itV" +
      "nCI_WRAkWMa7\",\"crv\":\"P-384\",\"alg\":\"ES384\"},{\"kty\":\"EC\",\"kid\":\"1\",\"use\":\"sig\",\"x\":\"IUk" +
      "0VFdRVnVVmdCfZxREU0pXmUk9fub4JVnqVZ5DTmI\",\"y\":\"DNr82q7z1vfvIjp5a73t1yKg2vhcUDKqdsKh_FFbBZs\",\"crv\":\"P-" +
      "256\",\"alg\":\"ES256\"},{\"kty\":\"RSA\",\"kid\":\"1\",\"use\":\"sig\",\"n\":\"lMRL3ng10Ahvh2ILcpEiKNi31ykHP" +
      "8Iq7AENbwvsUzfag4ZBtid6RFBsfBMRrS_dGx1Ajjkpgj3igGlKiu0ZsSeu3zDK2e4apJGonxOQr7W2Bpv0bltU3bVRUb6i3-jv5sok33l2lK" +
      "D6q7_UYRCmuo1ui2FGpwhorNVRFMe24HE895lvzGqDXUzsDKtMmZIt6Cj1WfJ68ZQ0gNByg-GVRtZ_BgZmyQwfTmPYxN_0uQ8usHz6kuSEysa" +
      "rzW_mUX1VEdzJ2dKBxmNwQlTW9v1UDvhUd2VXbGk1BvbJzFYL7z6GbxwhCynN-1bNb2rCFtRSI3UB2MgPbRkyjS97B7j34w\",\"e\":\"AQA" +
      "B\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("1"))), "", empty)))
        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES256),
          keyID = Some(KeyId("2"))), "", empty)))
        ecJwk <- keys2.headOption.flatMap(jwk => typed[EllipticCurveJsonWebKey](jwk).toOption)
          .toRight(OptionEmpty.label("ecJwk")).eLiftET[IO]
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("1")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("2")) && ecJwk.curve == `P-256`
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with not unique kids so disambiguate by use kty tests" in {
    // JSON content from a PingFederate JWKS endpoint modified by hand to fake up some semi-plausible cases (same kid used for different key types - no algs so crv is used on ECs)
    val json = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"3\",\"use\":\"sig\",\"x\":\"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9o" +
      "u3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\",\"y\":\"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrv" +
      "P2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"3\",\"use\":\"sig" +
      "\",\"x\":\"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\",\"y\":\"Bt0HwjlM4RoyCfq7DM9j34u" +
      "jq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"3\",\"use\":\"sig\"," +
      "\"x\":\"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\",\"y\":\"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\"," +
      "\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"3\",\"use\":\"sig\",\"n\":\"qqqF-eYSGLzU_ieAreTxa3Jj7zOy4uVKCpL" +
      "6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5wfE8HZNGapF9-oHO" +
      "794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_MSMHjJs49CHXtqp" +
      "ezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\",\"e\":\"AQAB\"},{" +
      "\"kty\":\"EC\",\"kid\":\"2\",\"use\":\"sig\",\"x\":\"Aeu8Jbm9XTwhwHcq19BthU6VIz4HU7qDG7CNae81RujWu3aSEWoX1aAV" +
      "Rh_ZMABfMKWCtXvhh2FEpSAcQRiKilfG\",\"y\":\"AOlx2rRLBLI3nh3eAlWI1ciFKWaw-6XEJw4o6nLXHRBVo92ADYJBItvRdKcBk-BYb4" +
      "Cewma7KtNuIK8zZ2HEen6d\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"2\",\"use\":\"sig\",\"x\":\"gcqegh2wqsL" +
      "gmikkGF1137rVf5QPhJb0hF7zwWNwSM5jyWwfwTlhNMc4V8FO01Jt\",\"y\":\"-bO4V5xtasOgWsrCGs_bydqT0o3O29cA-5Sl7aqSfB7Z5" +
      "-N3Dki5Ed2RZEU0Q7g0\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"2\",\"use\":\"sig\",\"x\":\"6elUcv15VpXlU9" +
      "95KVHZ3Jx6V8Cq7rCoodyIaXbQxS8\",\"y\":\"mHnmwkt-jhxWKjzx75egxVx2B25QiRzi5l0jNDF9hu8\",\"crv\":\"P-256\"},{\"k" +
      "ty\":\"RSA\",\"kid\":\"2\",\"use\":\"sig\",\"n\":\"wbcVJs-T_yP6TEWmdAqTo3qFsdtpffUEqVbxtaWr-PiXs4DTWtig6kYO1H" +
      "wim0j780f6pBgWTKAOBhGm4e3RQH86cGA-kC6uD1931OLM1tcRhoaEsz9jrGWn31dSLBX9H_4YqR-a1V3fov09BmfODE7MRVEqmZXHRxGUxXL" +
      "GZn294LxZDRGEKwflTo3QZDG-Yirzf4UnbPERmSJsz6KE5FkO1k1YWCh1JnPlE9suQZC6OXIFRYwVHUP_xo5vRxQ0tTO0z1YHfjNNpycLlCNO" +
      "oxbuN3f7_vUD08U2v5YnXs8DPGCO_nG0gXDzeioqVDa2cvDKhOtSugbI_nVtPZgWSQ\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":" +
      "\"1\",\"use\":\"sig\",\"x\":\"AeRkafLScUO4UclozSPJpxJDknmB_SM70lA4MLGY9AGwHIu1tTl-x9WjttYZNrQ6eE0bAWGb_0jgVcc" +
      "vz0SD7es-\",\"y\":\"AdIP5LQzH3oNFTZGO-CVnkvD35F3Cd611zYjts5frAeqlxVbB_l8UdiLFqIJVuVLoi-kFJ9htMBIo1b2-dKdhI5T" +
      "\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"1\",\"use\":\"sig\",\"x\":\"cLP7G_dHWU7CGlB3h2Rt-yr4cuT2-ybk6" +
      "Aq5zoBmzUo5jNrQR_IvrllfvdVfF1ub\",\"y\":\"-OzAuuaPViw3my3UAE3WiXOYlaa5MYz7dbMBSZjZhretKm118itVnCI_WRAkWMa7\"," +
      "\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"1\",\"use\":\"sig\",\"x\":\"IUk0VFdRVnVVmdCfZxREU0pXmUk9fub4JVnq" +
      "VZ5DTmI\",\"y\":\"DNr82q7z1vfvIjp5a73t1yKg2vhcUDKqdsKh_FFbBZs\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":" +
      "\"1\",\"use\":\"sig\",\"n\":\"lMRL3ng10Ahvh2ILcpEiKNi31ykHP8Iq7AENbwvsUzfag4ZBtid6RFBsfBMRrS_dGx1Ajjkpgj3igGl" +
      "Kiu0ZsSeu3zDK2e4apJGonxOQr7W2Bpv0bltU3bVRUb6i3-jv5sok33l2lKD6q7_UYRCmuo1ui2FGpwhorNVRFMe24HE895lvzGqDXUzsDKtM" +
      "mZIt6Cj1WfJ68ZQ0gNByg-GVRtZ_BgZmyQwfTmPYxN_0uQ8usHz6kuSEysarzW_mUX1VEdzJ2dKBxmNwQlTW9v1UDvhUd2VXbGk1BvbJzFYL7" +
      "z6GbxwhCynN-1bNb2rCFtRSI3UB2MgPbRkyjS97B7j34w\",\"e\":\"AQAB\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS256),
          keyID = Some(KeyId("1"))), "", empty)))
        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES256),
          keyID = Some(KeyId("2"))), "", empty)))
        ecJwk2 <- keys2.headOption.flatMap(jwk => typed[EllipticCurveJsonWebKey](jwk).toOption)
          .toRight(OptionEmpty.label("ecJwk2")).eLiftET[IO]
        keys3 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES512),
          keyID = Some(KeyId("2"))), "", empty)))
        ecJwk3 <- keys3.headOption.flatMap(jwk => typed[EllipticCurveJsonWebKey](jwk).toOption)
          .toRight(OptionEmpty.label("ecJwk3")).eLiftET[IO]
        keys4 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(ES384),
          keyID = Some(KeyId("2"))), "", empty)))
        ecJwk4 <- keys4.headOption.flatMap(jwk => typed[EllipticCurveJsonWebKey](jwk).toOption)
          .toRight(OptionEmpty.label("ecJwk4")).eLiftET[IO]
        keys5 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(HS256)), "", empty)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("1")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("2")) && ecJwk2.curve == `P-256` &&
          keys3.length == 1 && keys3.head.keyID.contains(KeyId("2")) && ecJwk3.curve == `P-521` &&
          keys4.length == 1 && keys4.head.keyID.contains(KeyId("2")) && ecJwk4.curve == `P-384` &&
          keys5.isEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with id token from ping federate" in {
    // JWKS from a PingFederate JWKS endpoint along with a couple ID Tokens (JWTs) it issued
    val jwtCs1 = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhMDBrIn0.eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiUXhSYjF2Z2tpSE" +
      "90MlZoNVdST0pQUiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5MzM4MiwiZXhwIjoxNDIxMDkzOTgyLCJ" +
      "ub25jZSI6Im5hbmFuYW5hIiwiYWNyIjoidXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQiLCJhdXRoX3Rp" +
      "bWUiOjE0MjEwOTMzNzZ9.OlvyiduU_lZjcFHXchOzOptaBRt2XW_W2LATCPnfmi_mrfz5BsCvCGmTq6HCBBuOVF0BcbLA1h4ls3naPVu4YeWc" +
      "1jkKFmlu5UwAdHP3fdUvAQdByyXDAxFgYIwl06EF-qpEX7r5_1D0OnrReq55n_SA-iqRync2nn5ZhkRoEj77E5yMFG93yRp4IP-WNZW3mZjkF" +
      "PnSCEHfRU0IBURfWkPzSkt5bKx8Vr-Oc1I5hFUyKyap8Ky17q_PoF-bHZG7MZ8B5Q5RvweVbdudain_yH3VAujDtqN_gu-7m1Vt6WdQpFIOGs" +
      "VSpCK0-wtV3MvXzSKLk-5qwdVSI4GH5K_Q9g"
    val jwtCs2 = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjhhMDBsIn0.eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiRmUwZ1h1UGpmcH" +
      "oxSHEzdzRaaUZIQiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5Mzg1OSwiZXhwIjoxNDIxMDk0NDU5LCJ" +
      "ub25jZSI6ImZmcyIsImFjciI6InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkIiwiYXV0aF90aW1lIjox" +
      "NDIxMDkzMzc2fQ.gzJQZRErEHI_v6z6dZboTPzL7p9_wXrMJIWnYZFEENgq3E1InbrZuQM3wB-mJ5r33kwMibJY7Qi4y-jvk0IYqQ"
    val jwksJson = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"8a00r\",\"use\":\"sig\",\"x\":\"AZkOsR09YQeFcD6rhINHWAaAr8D" +
      "Mx9ndFzum50o5KLLUjqF7opKI7TxR5LP_4uUvG2jojF57xxWVwWi2otdETeI-\",\"y\":\"AadJxOSpjf_4VxRjTT_FdAtFX8Pw-CBpaoX-O" +
      "QPPQ8o0kOrj5nzIltwnEORDldLFIkQQzgTXMzBnWyQurVHU5pUF\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"8a00q\",\"" +
      "use\":\"sig\",\"x\":\"3n74sKXRbaBNw9qOGslnl-WcNCdC75cWo_UquiGUFKdDM3hudthywE5y0R6d2Li8\",\"y\":\"YbZ_0lregvTb" +
      "oKmUX7VE7eknQC1yETKUdHzt_YMX4zbTyOxgZL6A38AVfY8Q8HWd\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"8a00p\"," +
      "\"use\":\"sig\",\"x\":\"S-EbFKVG-7pXjdgM9SPPw8rN3V8-2uX4bNg4y8R7EhA\",\"y\":\"KTtyNGz9B9_QrkFf7mP90YiH6F40fAY" +
      "fqpzQh8HG7tc\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"8a00o\",\"use\":\"sig\",\"n\":\"kM-83p_Qaq-1FuxL" +
      "HH6Y7jQeBT5MK9iHGB75Blnit8rMIcsns72Ls1uhEYiyB3_icK7ibLr2_AHiIl7MnJBY2cCquuwiTccDM5AYUccdypliSlVeAL0MBa_0xfpvB" +
      "Jw8fB45wX6kJKftbQI8xjvFhqSIuGNyQOzFXnJ_mCBOLv-6Nzn79qWxh47mQ7NJk2wSYdFDsz0NNGjBA2VQ9U6weqL1viZ1sbzXr-bJWCjjEY" +
      "mKC5k0sjGGXJuvMPEqBY2q68kFXD3kiuslQ3tNS1j4d-IraadxpNVtedQ44-xM7MC-WFm2f5eO0LmJRzyipGNPkTer66q6MSEESguyhsoLNQ" +
      "\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"8a00n\",\"use\":\"sig\",\"x\":\"ADoTal4nAvVCgicprEBBFOzNKUKVJl1P" +
      "h8sISl3Z3tz7TJZlQB485LJ3xil-EmWvqW1-sKFl7dY2YtrGUZvjGp0O\",\"y\":\"AXVB58hIK7buMZmRgDU4hrGvcVQLXa-77_F755OKIk" +
      "uWP5IJ6GdjFvaRHfIbbHMp-whqjmRrlwfYPN1xmyCGSzpT\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"8a00m\",\"use\"" +
      ":\"sig\",\"x\":\"5Y4xK9IBGJq5-E6QAVdpiqZb9Z-_tro_rX9TAUdWD3jiVS5N-blEnu5zWzoUoiJk\",\"y\":\"ZDFGBLBbiuvHLMOJ3" +
      "DoOSRLU94uu5y3s03__HaaaLU04Efc4nGdY3vhTQ4kxEqVj\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"8a00l\",\"use" +
      "\":\"sig\",\"x\":\"CWzKLukg4yQzi4oM-2m9M-ClxbU4e6P9G_HRn9A0edI\",\"y\":\"UB1OL_eziV6lA5J0PiAuzoKQU_YbXojbjh0s" +
      "fxtVlOU\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"8a00k\",\"use\":\"sig\",\"n\":\"ux8LdF-7g3X1BlqglZUw3" +
      "6mqjd9P0JWfWxJYvR6pCFSyqLrETc-fL9_lTG3orohkGnEPe7G-BO65ldF44pYEe3eZzcEuEFtiO5W4_Jap1Z430vdYgC_nZtENIJDWlsGM9e" +
      "v-cOld7By-8l3-wAyuspOKZijWtx6K57VLajyUHBSmbUtaeCwHQOGyMOV1V-cskbTO2u_HrLOLLkSv9oZrznAwpx_paFHy-aAsdFhb7EiBzwq" +
      "qHQButo3aT3DsR69gbW_Nmrf6tfkril6B3ePKV4od_5jowa6V3765K6v2L4NER7fuZ2hJVbIc0eJXY8tL3NlkBnjnmQ8DBWQR81Ayhw\",\"e" +
      "\":\"AQAB\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        jws1 <- JsonWebSignature.parse(jwtCs1).eLiftET[IO]
        primitives1 <- EitherT(jwks.verificationPrimitives[IO](jws1))
        _ <- EitherT(jws1.check[IO](primitives1.head.key, primitives1.head.configuration))
        _ <- EitherT(JsonWebToken.getClaims[IO](jwtCs1)(jwks.verificationPrimitives)(jwks.decryptionPrimitives))
        jws2 <- JsonWebSignature.parse(jwtCs2).eLiftET[IO]
        primitives2 <- EitherT(jwks.verificationPrimitives[IO](jws2))
        _ <- EitherT(jws2.check[IO](primitives2.head.key, primitives2.head.configuration))
        _ <- EitherT(JsonWebToken.getClaims[IO](jwtCs2)(jwks.verificationPrimitives)(jwks.decryptionPrimitives))
      yield
        primitives1.length == 1 && primitives2.length == 1
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with no kids" in {
    val json = "{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9ou3taXkQ6-nNoUf" +
      "ZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\",\"y\":\"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrvP2ZGC8uX1cH9Ib" +
      "EpcmHzXI2yAx3UZS8JiMueU6J_YEI\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"wwxLXWB-6zA06R6hs2" +
      "GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\",\"y\":\"Bt0HwjlM4RoyCfq7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z" +
      "81jqpPw0F_Xm\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2Ds" +
      "axjJ6vbU\",\"y\":\"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\",\"crv\":\"P-256\"},{\"kty\":\"OKP\",\"crv\":" +
      "\"Ed25519\",\"x\":\"EmqN44zWvm_L4PRJqrapUgY8EbDj-A5mhW1BBoad71c\"},{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":" +
      "\"gxFiyHTiib96JZp42H852rQ9tV54vP2zUcBhhPkZ6X0\"},{\"kty\":\"RSA\",\"use\":\"sig\",\"n\":\"qqqF-eYSGLzU_ieAreT" +
      "xa3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5" +
      "wfE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr" +
      "_MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\"," +
      "\"e\":\"AQAB\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        primitives1 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(RS256)), "", empty)))
        primitives2 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES256)), "", empty)))
        primitives3 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES512)), "", empty)))
        primitives4 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES384)), "", empty)))
        primitives5 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(EdDSA)), "", empty)))
      yield
        primitives1.length == 1 && primitives2.length == 1 && primitives3.length == 1 && primitives4.length == 1 &&
          primitives5.length == 1
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with some kids symmetric selections" in {
    val json = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"uno\",\"k\":\"9gfpc39Jq5H5eR_JbwmAojgUlHIH0GoKz7COz000001\"},{" +
      "\"kty\":\"oct\",\"kid\":\"two\",\"k\":\"5vlp7BaxRr-a9pOKK7BKNCo88u6cY2o9Lz6-P--_01j\"},{\"kty\":\"oct\",\"kid" +
      "\":\"trois\",\"k\":\"i001cccx6-7rP5p91NeHi3K-jcDjt8N12o3bIeWA081\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        keys1 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(HS256),
          keyID = Some(KeyId("uno"))), "", empty)))
        keys2 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(HS256),
          keyID = Some(KeyId("trois"))), "", empty)))
      yield
        keys1.length == 1 && keys1.head.keyID.contains(KeyId("uno")) &&
          keys2.length == 1 && keys2.head.keyID.contains(KeyId("trois"))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with select with verify signature disambiguate" in {
    val jwksJson = "{\"keys\":[{\"kty\":\"EC\",\"x\":\"yd4yK8EJWNY-fyB0veOTNqDt_HqpPa45VTSJjIiI8vM\",\"y\":\"UspqZi9" +
      "nPaUwBY8kD6MPDHslh5f6UMnAiXsg1l3i6UM\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"x\":\"3WPq7AnMkQekA1ogYFqNS5NBOXP" +
      "s68xadKvtsn4pgas\",\"y\":\"CEvQFmGwKv96TQYRrgS-nFl9xWfN8PuLnIwBVmtpfp0\",\"crv\":\"P-256\"},{\"kty\":\"EC\"," +
      "\"x\":\"DUYwuVdWtzfd2nkfQ7YEE_3ORRv3o0PYX39qNGVNlyA\",\"y\":\"qxxvewtvj61pnGDS7hWZ026oZehJxtQO3-9oVa6YdT8\"," +
      "\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"n\":\"mGOTvaqxy6AlxHXJFqQc5WSfH3Mjso0nlleF4a1ebSMgnqpmK_s6BSP0v9CyKyn_s" +
      "BNpsH6dlOsks4qwb88SdvoWpMo2ZCIt8YlefirEaT9J8OQycxMvk7U1t6vCyN8Z68FrwhzzsmnNI_GC723OfMhcEZiRGNRJadPCMPfY3q5PgR" +
      "rCjUS4v2hQjaicDpZETgbGxWNuNiIPk2CGhG3LJIUX4rx5zrFPQuUKH2Z1zH4E39i3Ab0WBATY0warvlImI5_rT-uCvvepnaQ6Mc4ImpS3anL" +
      "NjfPlaNVajl5aRuzzRO77XePN-XzFJUVbC_v1-s2IcJf8uB-PMKAtRqz_kw\",\"e\":\"AQAB\"},{\"kty\":\"RSA\",\"n\":\"4SoqXJ" +
      "ikILVhuwpeOYjbi_KGFXfvMaiBtoDm7nKsVc8ayQ4RBGbQdqHIt6gxSSTHrRSbQ2s5lAHfeyBJ9myQitCwxHFzjIDGcp5_u0wNWJbWUsDnbS-" +
      "pwAQsZXZ3m6u_aDEC4sCTjOuotzwJniehVAkm2B1OnoYVhooKt9CTjVj1hwMf8Cpr171Vt559LyzUhRml6Se_AJWG_oFLV2c5ALCi2USfq2G_" +
      "zoXFt9Kc93LJ9XoPy-hbQXA13OXwi9YL_BDLk8nd7QfaUgm77-j6RbOYg0l0PTloggw7km7M1D8iDASfkuII-Dzqedcm3KQb0Quo20HkirlIk" +
      "67E-jOk6Q\",\"e\":\"AQAB\"}]}"
    val run =
      for
        jwsWith1stEC <- JsonWebSignature.parse("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjo" +
          "idGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.04tBvYG5QeY8lniGnkZNHMW8b0OPCN6XHuK9g8fsOz8uA_r0Yk-biMkWG7l" +
          "tOMCFSiiPvEu7jNWfWbk0v-hWOg").eLiftET[IO]
        jwsWith2ndEC <- JsonWebSignature.parse("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjo" +
          "idGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.uIRIFrhftV39qJNOdaL8LwrK1prIJIHsP7Gn6jJAVbE2Mx4IkwGzBXDLKMu" +
          "lM1IvKElmSyK_KBg8afywcxoApA").eLiftET[IO]
        jwsWith3rdEC <- JsonWebSignature.parse("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjo" +
          "idGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.21eYfC_ZNf1FQ1Dtvj4rUiM9jYPgf1zJfeE_b2fclgu36KAN141ICqVjNxQ" +
          "qlK_7Wbct_FDxgyHvej_LEigb2Q").eLiftET[IO]
        jwsWith1stRSA <- JsonWebSignature.parse("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIj" +
          "oidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.aECOQefwSdjN1Sj7LWRBV3m1uuHOFDL02nFxMWifACMELrdYZ2i9W_c6Co" +
          "0SQoJ5HUE0otA8b2mXQBxJ-azetXT4YiJYBpNbKk_H52KOUWvLoOYNwrTKylWjoTprAQpCr9KQWvjn3xrCoers4N63iCC1D9mKOCrUWFz" +
          "Dy--inXDj-5VlLWfCUhu8fjx_lotgUYQVD03Rm06P3OWGz5G_oksJ7VpxDDRAYt7zROgmjFDpSWmAtNEKoAlRTeKnZZSN0R71gznBsofs" +
          "-jJ8zF0QcFOuAfqHVaDWnKwqS0aduZXm0s7rH61e4OwtQdTtFZqCPldUxlfC7uzvLhxgXrdLew").eLiftET[IO]
        jwsWith2ndRSA <- JsonWebSignature.parse("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIj" +
          "oidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.pgBu9S8g7MC2BN9YNlWD9JhjzWbQVjqpmErW4hMFncKD8bUidIbMBJSI3U" +
          "RXvnMJrLrAC5eB2gb6DccF_txQaqX1X81JbTSdQ44_P1W-1uIIkfIXUvM6OXv48W-CPm8xGuetQ1ayHgU_1ljtdkbdUHZ6irgaeIrFMgZ" +
          "X0Jdb9Eydnfhwvno2oGk3y6ruq2KgKABIdzgvJXfwdOFGn1z0CxwQSVDkFRLsMsBljTwfTd0v3G8OXT8WRMZMGVyAgtKVu3XJyrPNntVq" +
          "rzdgQQma6S06Y9J9V9t0AlgEAn2B4TqMxYcu1Tjr7bBL_v83zEXhbdcFBYLfJg-LY5wE6rA-dA").eLiftET[IO]
        jwsWithUnknownEC <- JsonWebSignature.parse("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTEyNywiYXV" +
          "kIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.UE4B0IVPRip-3TDKhNAadCuj_Bf5PlEAn9K94Zd7mP25WNZwxDbQpDE" +
          "lZTZSp-3ngPqQyPGj27emYRHhOnFSAQ").eLiftET[IO]
        jwsWith384EC <- JsonWebSignature.parse("eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTIzMSwiYXVkIjo" +
          "idGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9.NyRtG_eFmMLQ0XkW5kvdSpzYsm6P5M3U8EBFKIhD-jw8E7FOYw9PZ3_o1PW" +
          "uLWH3XeArZMW7-bAIVxo2bHqJsSUtB6Tf0NWPtCpUF2c1vbuRXEXkGrCUmc4sKyOBjimC").eLiftET[IO]
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        firstJwk <- Try(jwks.keys.head).asError.eLiftET[IO]
        firstKey <- EitherT(firstJwk.toKey[IO]())
        secondJwk <- Try(jwks.keys(1)).asError.eLiftET[IO]
        secondKey <- EitherT(secondJwk.toKey[IO]())
        thirdJwk <- Try(jwks.keys(2)).asError.eLiftET[IO]
        thirdKey <- EitherT(thirdJwk.toKey[IO]())
        fourthJwk <- Try(jwks.keys(3)).asError.eLiftET[IO]
        fourthKey <- EitherT(fourthJwk.toKey[IO]())
        fifthJwk <- Try(jwks.keys(4)).asError.eLiftET[IO]
        fifthKey <- EitherT(fifthJwk.toKey[IO]())
        primitives1stEC <- EitherT(jwks.verificationPrimitives[IO](jwsWith1stEC))
        primitive1stEC <- EitherT(jwsWith1stEC.checkWithPrimitives[IO](primitives1stEC))
        primitives2ndEC <- EitherT(jwks.verificationPrimitives[IO](jwsWith2ndEC))
        primitive2ndEC <- EitherT(jwsWith2ndEC.checkWithPrimitives[IO](primitives2ndEC))
        primitives3rdEC <- EitherT(jwks.verificationPrimitives[IO](jwsWith3rdEC))
        primitive3rdEC <- EitherT(jwsWith3rdEC.checkWithPrimitives[IO](primitives3rdEC))
        primitivesUnknownEC <- EitherT(jwks.verificationPrimitives[IO](jwsWithUnknownEC))
        _ <- EitherT(jwsWithUnknownEC.checkWithPrimitives[IO](primitivesUnknownEC).map(_.swap.asError))
        keys384EC <- EitherT(jwks.filterForVerification[IO](jwsWith384EC))
        primitives1stRSA <- EitherT(jwks.verificationPrimitives[IO](jwsWith1stRSA))
        primitive1stRSA <- EitherT(jwsWith1stRSA.checkWithPrimitives[IO](primitives1stRSA))
        primitives2ndRSA <- EitherT(jwks.verificationPrimitives[IO](jwsWith2ndRSA))
        primitive2ndRSA <- EitherT(jwsWith2ndRSA.checkWithPrimitives[IO](primitives2ndRSA))
      yield
        primitives1stEC.length == 3 && primitive1stEC.key.exists(_.equals(firstKey)) &&
          primitives2ndEC.length == 3 && primitive2ndEC.key.exists(_.equals(secondKey)) &&
          primitives3rdEC.length == 3 && primitive3rdEC.key.exists(_.equals(thirdKey)) &&
          primitivesUnknownEC.length == 3 && keys384EC.isEmpty &&
          primitives1stRSA.length == 2 && primitive1stRSA.key.exists(_.equals(fourthKey)) &&
          primitives2ndRSA.length == 2 && primitive2ndRSA.key.exists(_.equals(fifthKey))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with select with verify signature disambiguate different RSA sizes 1" in {
    val run =
      for
        rsaJwk2048 <- decode[Id, AsymmetricJsonWebKey]("{\"kty\":\"RSA\",\"n\":\"s3xFORqMy1xG-9Xx0i2y2rXxtoBCpMPeZd4" +
          "F4do8RWdGRKJQ7Vrj5dtgym0xZoV70SR92d3h0ofLAGTswk6t0IxtO0Y5UHN_mOkdxXTJpYLiVzR-1xIttOhVlHjXnZzb_cCXoXoNRnY8" +
          "RqVPDN386Wpx4f60MpHYHsrKn-r4LY7LHH8Bt70t1KGIQNU9fPdlClItlpKPSWmiGAhh6P6aJi8SVkx5wLtz0Y95R7jqb6EPRXTKCYD-y" +
          "WMWik1p-st2wo4B7LyLw_wCRkimAX2jssswGL9Rpc5MYaA5TPaQmJjruT1IEv50-g8f7pxioDz7tNAfbggyDYUPZDm-EFcdhw\",\"e\"" +
          ":\"AQAB\",\"d\":\"Q4qiKgj5rpU9CQvLgkI8Kd2J5hmB-qrSiBbys7kCMUPZx34lYgxv8lGJrONGUcQtgdhvm4rJrgX3uGBCUCR3eCF" +
          "AAaw9aS7td0dSMrnuH-CO-C4DBUAL_yXm_oYy7VbX2jedV-CsGjXoHNWcV8U5pUSvMlI80ULcx0mc0m0Dk3ClOSTVuodV8WBsad9RqhcL" +
          "PUS8oMH-Iqb2l5u7bxarIiVAY3f75LNw9F194XtUKl7j5kBi3S4Qp39zmxu_NUK_sSWP1pWXuMxYHJ1cnvbemgIL5zzMmKSpoNzgrAtmC" +
          "-9ReDWW9ZoGt5OruwLgGpGdDov4y62vel-bUcKT3vMOwQ\",\"p\":\"35rWLZ9j8bcEbSCNdHguSmMHyIL31xIVspPVmZE2vrswYssx3" +
          "DyF2oF6miXz4cwd_TnUo0wbN2tIM8kUY-zc2LPVqHzxJbF4GMf3cpYRSbYW0r9vV0jjjZQXNer7_HCQNZC1pWxRA7817UQMn3reCRKVhK" +
          "UzzdYvim0INeYppTc\",\"q\":\"zX0cv0ILtaQuPv9bU2phiTi9fj5oDeOGvq5sF46hHYhDcIb3_ju9oF-bG45gg6DNWXNH3YV6umA-B" +
          "asejO0W0ir7r9IE7GPQPVtMpDWDVo1w-fRDS4BiSFOaOojHoY3POz087SDIGIC5kNmz6nOkQDb38urPVamMT1461iWUcjE\",\"dp\":" +
          "\"qYUEfSAKsFTVCTqVo0f9qC192BjadnXidzk2xa7etyjI3Q05ZsOHowlofnbpdzS9Q55VQ9vOAmzWF1SJndwT7kIgaBUY6T-rUfY_9eI" +
          "phx2CHhI-AgljYpF0K09T7KUV31YvMBN3NAUBiDh_7WRD8tLhAegQ5ytLbYGNqPcueW8\",\"dq\":\"EmLnd5WJRq9yE-D1YvlZ0NVq3" +
          "yjmVpfNLrKcqV7xu5q9rgvllLHzva3QSx7qM9znguF1xLR0zshdxFQTX7i3GgcOjiTUm_IyZ8sLiIXhQpVVTog0nUTXhnE0k5g5hJMTv9" +
          "Ey6mTMgqTB9dwE5S2DvNsuRGYONzP8gf2EdjTWm4E\",\"qi\":\"YMui-he-fz_wv-ZdV--r6j4Utdz9p4BtjtfEA1_XQ40U944EIBpu" +
          "ZToKgE9Fquqqz6E3oc_2cgr3NBEXMz2hdUgkM6s4jz-Mtc2PZRSVRQZq7RTnCBaahHr9mQhaEanoae69M79SvkcTGK_APnodFrfWZJfEU" +
          "PffK0izKMM5KTs\"}").eLiftET[IO]
        rsaJwk4096 <- decode[Id, AsymmetricJsonWebKey]("{\"kty\":\"RSA\",\"n\":\"oOtx-ZO3KSNr_Wy5VJjXUJOuZq70nyd4QWT" +
          "XsM4bQGqZlGPtMAqjxo-Qkw6WGubJxABtDxKUJBlmNgqieEFrFixV-_-DaujvoaXYi4C1T5a7WdIIYyEZmTztoeVnyWusYJBRpjONu4uM" +
          "IfT-flbkmQu9MFs_0FEApLrhiMkujXxOffmw8gBVE2dmSwU74IpC8VsaZBInjr6B0-LLCYuFaRHfF5Nnq2wV3Roo8m_rhH-yrnEf9fbao" +
          "ZH6rPTrBWc_thJq-X7qeFmHAyELCM_xlGSwnz2H8jPTRWJU4feTS7Ons71Ig0ot7NJF4GBHJ4HyeBjj3a2LQUA14kiDfDAkJntS3egVAI" +
          "w4No7We-pr5JdOPIZztwriZ2w_8aUDhqBNgXHuYAekQLj0qjRcwFoENy5pD-FsIXUeDO7agNbpbl-Wlgos2M97eaut359HPmZ7veLj0zh" +
          "K3Uy6nsT0SO7-JhrqEnALn-AxXhU0yN3AntwU_qhjrtgrxcSYVYGN5os1xvbBoKmtlQik_vWO5JoiRXpz2EtT9EUQcdY16M1eTjStOnlk" +
          "9BcFSvbNsHj_skEAtP_iCAdlQkkKYqzhCZSK1QCAp20_F2hlMlx-MS1dWgZjjf5MDebsTlu7c6IXxhAbM42m5EUQdpPp8dv0ValaaCU_g" +
          "L7_G0-gXlqM-Yl23K0\",\"e\":\"AQAB\",\"d\":\"EmxCJS-bJZOPlnjvEtdYtznhGpJnIR10sA_qfaxrBEnwAUQbcIeXTnE7PQrLd" +
          "pL7gHwIAFTBLwzVXdSD2z6qEuTKh0oucnvui1QgYYA_wbfhBRx9p1OvyZJnJkTMSAwStQ9wuZVnYZRNW8nfpPkvvLHSXAnmWWQcrb9TeM" +
          "SHlt0nY1bFwj71fn41ANu9iixqE5W5hMFrU_VNicOKOTKG-It6Pgm7Ma3zJtgK3g6gKRAxlbUP0qoLR7odt9VmXrz-V0ruglfcYiDlyx7" +
          "qU3zzDGkmq2Rw_vKd-nCShThB3cXYqkQ-XAGPFnDQXSrImqZO6x72X3ex3KuMP7bLjtk4Ghx3yFxRUNJAaQEKgMTvFNsybx7oCPTOXxAV" +
          "hxCeEuv1o1b4g6mCs9XVlUPVnZwt4fW-QHeenqeLe-Y3gsPEAkGdsZoEL0eQqjwVad-MdA0r3BHJQRjBp2YDujF5V8ypJeR6CE1ILlc2W" +
          "4DvhzgpGF3m2RUUqSXVj1aOCciZGAwtU-Lhgg4hDkv8ZV6nKE-O2FbI_126n41e-PeBoh8214RAJeAW82y3AAP3lwd38EfLIxt17rQ2bK" +
          "IDx4kJmgtW5a4LiAshvYN3SgqtyKvJSbDllLIy6OdXWlSv_ogcbeDnY3F5MNBfn6moGupsvOWkOH3zX6TxifBDjsebwMab8UE\",\"p\"" +
          ":\"9FQGthSnO6TSEFODI-NjyyqdWwWGDHueIjAKBB76hnc5XAojVJepmbnD3HrUm3ujqbA9uGygdTl88gHiv-nDxYkRL9foNmTdCrzIqq" +
          "xZnYfmHQjCbRXbc8oFd-bDRNLMZFX7TJbnaSugdgDNcVLTH8nd-qKH4VLdGnrTiQrq4FjEEDSdgwfzDbM9LrNxT_9KZlCsEj9eTqGJW5f" +
          "ugU2QvfVvdocnRKwMkg22rQ8Rt2IDexD3LSLcZwjF3yd1Bxm0VA1ks-Gc229NSyETGf45eNn9M6Uxb_jXM7hpdxAQyVh8Ua_bMzh6u5ED" +
          "giymigwgQx79eJswyzSeYmD99VwmHQ\",\"q\":\"qJtjOBXxIMQkD5I60PqbQ8l3ehIs3uXaOzMt8beyEzLfSH77fu-cZGkYLYtGnKuC" +
          "kt_Yv-gN6IQgBF9kE7Jic5FIITSnC2Qjem7BAmDV6-2f9xRSisNznR-tScsMMtIKVFm4Gr0rZpZICRNKSOZJ4EhL17JEqmUihw--9H1dj" +
          "C1K9Emgy9nJhgbUrWuJ_ShF2PZeUet_ABI6P11m3wUmCZScf3o4prqqJQcdjVTYXdSA6XfnzTilIDFCSlNJY4uAYZ5ZzOxQ2W3x1GXXFl" +
          "dmWv8wplylumWbY9jCCRUVWJiZqD0-cqBVVNuofVg0Po4usndlNGcpVp2HbWxJBJKL0Q\",\"dp\":\"XGDkxLVcYZ242vlobQpNsgRjy" +
          "IV3IIMg0BZPwy0fVfYAFv-ySgqp0ni9SECc4EjIIaGERJW1uXzJ9AqofB1bqvVfLTK6Fs7eEHA-guF1ZK18YN_t-ya3ebkZhjMXA4-cPh" +
          "eQU23_AvG-0r8M7lr9flhp-Ji5PYWCGb_0-SzKj5agUuxB3cgEqtppOJ4aKsAAllzMIn4ZHyvObnYsdHEqV9hTk4IYY8uVWSecOSSocyi" +
          "43jAU9NjocoCLqAsYIV4jo2AJAkY8c29KzywrN7m6ayoopP1Biu-QFnsUTTMi1a4CGzSdcWlaZk62_-H3-dwJ2rb96TrsIPi9Jb88Zie4" +
          "NQ\",\"dq\":\"dfX4zbV0NONlA0vgQHMEi8F5CHuMzwlqy_47h6BoQsxVsOe-VomXFhz84GhPp67KtK1NfL4CdQlzSPvgDXPBM2-SUkD" +
          "_GZYeyDqSaHKNV_mw7_FU6mZiDayq1TTsvOV8epUmm_Z7VdOQZGENmMEdMIAEJ80-AySsqmeWxoCrITZS-WRFzjj5p_5Bb28MZIR3kZqU" +
          "VKX4_XjDLa_QF_oHKa7CauF8nxF7llpLD6Url0HkSvMrxsV5qXMtGMj6UF26HRHna9ptmiE0jtANUkEliEZ_p_SrsiQCOjHdVvNcMtbYs" +
          "f7fIN0RtkPTtpYuPxHEk_G6aZY_Mq0VobWfxEYu8Q\",\"qi\":\"fZKGdPoeWTVRR5sbkP7eh_Kv8kYK4FDmHqwyt4e6Wgb-Sdnn2ZhM" +
          "I-4YzVMtSer167crPXBkuDbCCdXr2yBMT4XsyjFzKqr7ZqU-vQjRgYD7lDJtWF5KLLmxt8loM3tO0Ei1dg1dr8Vlc4U8JzIjpRmQxLqSk" +
          "qU9cpIPXcTzjOH8SYWi9IZhTLanwpUEYczfb2h0wkEVNY2zZrONkF7aj-fjkVxpkuDVDx3m6Kc7-5JgX7Kt4p7t-JLiym-yabf1yEeU3D" +
          "GS690Xf65XBQZKRUr4omMPPXm9_aTop7mtlZATqop7jeqeGSRuwaoilBZtJoidLxi2F2eUWVhASZg2Vg\"}").eLiftET[IO]
        // signed with the 4096 one
        jws <- JsonWebSignature.parse("eyJhbGciOiJSUzUxMiJ9.eyJjbGFpbSI6InZhbHVlIn0.gVe8O1YzNdOlJmcy6s5i6E1TH9oMNQqN" +
          "sYYoRjgPDNLK-daApzH2fkS7D1VWaBJc50sETNiy6VRzj_ZGTIxJYFRi1HqaQuos62VF1_DdLx2PbGSMoD2Orw6sBuBK179jNYOQ8RBwE" +
          "fbVmsHAQATZtc5hRxFmpfcJ_Ml3_ELoPRj-LNF5eygPaHRaVWm-Gjy1mwm7LQ4vinoWB2OhHnO9if-muYEJFLMzfZDAuq4EKnsze5XWuw" +
          "rh8c0eDmJzt_KJek1cTFfWsROydyohBNJWXTtP87Ee3jFw72V0i22zWc0AHo3ydr5F-g0QW7JoNfJwTd6Wr2lqTP-WVTQklawqM2uZ6E6" +
          "uElWcokFwYBFvUa1FMvD1bYQQLXklFGRJ33yGOwozz2L6-QATVjyyN_4oHmFUMwjSWjPQVJvqHZOB5vH6w7dc9CKtMgBCh4SNJMW3pmY1" +
          "bzoTDEUuOOgrGiPdipG5si7HgPwB3DrcE3ZUeYXeNaVjoOOCzfLwRzQG2hdrsH5He16RuB-EcGzk4tebwiHETJsWwW2PGY5DVRYAF80Iv" +
          "jUkF1L4iwKGNwAnO5t3BCHSrxJxGrNWoH--puEMTystNOmKtcgpp8XrmMA3Wd92_aNiIXioj82VAkBkuUBoDMskyedR9V0HqVuBc8EIpv" +
          "vQHgqz3LiIJdHRsZKj0Ts").eLiftET[IO]
        rsaKey4096 <- EitherT(rsaJwk4096.toKey[IO]())
        primitives <- EitherT(JsonWebKeySet(rsaJwk2048, rsaJwk4096).verificationPrimitives[IO](jws))
        primitive <- EitherT(jws.checkWithPrimitives[IO](primitives))
      yield
        primitive.key.exists(_.equals(rsaKey4096))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with select with verify signature disambiguate different RSA sizes 2" in {
    val run =
      for
        rsaJwk2048 <- decode[Id, AsymmetricJsonWebKey]("{\"kty\":\"RSA\",\"n\":\"s3xFORqMy1xG-9Xx0i2y2rXxtoBCpMPeZd4" +
          "F4do8RWdGRKJQ7Vrj5dtgym0xZoV70SR92d3h0ofLAGTswk6t0IxtO0Y5UHN_mOkdxXTJpYLiVzR-1xIttOhVlHjXnZzb_cCXoXoNRnY8" +
          "RqVPDN386Wpx4f60MpHYHsrKn-r4LY7LHH8Bt70t1KGIQNU9fPdlClItlpKPSWmiGAhh6P6aJi8SVkx5wLtz0Y95R7jqb6EPRXTKCYD-y" +
          "WMWik1p-st2wo4B7LyLw_wCRkimAX2jssswGL9Rpc5MYaA5TPaQmJjruT1IEv50-g8f7pxioDz7tNAfbggyDYUPZDm-EFcdhw\",\"e\"" +
          ":\"AQAB\",\"d\":\"Q4qiKgj5rpU9CQvLgkI8Kd2J5hmB-qrSiBbys7kCMUPZx34lYgxv8lGJrONGUcQtgdhvm4rJrgX3uGBCUCR3eCF" +
          "AAaw9aS7td0dSMrnuH-CO-C4DBUAL_yXm_oYy7VbX2jedV-CsGjXoHNWcV8U5pUSvMlI80ULcx0mc0m0Dk3ClOSTVuodV8WBsad9RqhcL" +
          "PUS8oMH-Iqb2l5u7bxarIiVAY3f75LNw9F194XtUKl7j5kBi3S4Qp39zmxu_NUK_sSWP1pWXuMxYHJ1cnvbemgIL5zzMmKSpoNzgrAtmC" +
          "-9ReDWW9ZoGt5OruwLgGpGdDov4y62vel-bUcKT3vMOwQ\",\"p\":\"35rWLZ9j8bcEbSCNdHguSmMHyIL31xIVspPVmZE2vrswYssx3" +
          "DyF2oF6miXz4cwd_TnUo0wbN2tIM8kUY-zc2LPVqHzxJbF4GMf3cpYRSbYW0r9vV0jjjZQXNer7_HCQNZC1pWxRA7817UQMn3reCRKVhK" +
          "UzzdYvim0INeYppTc\",\"q\":\"zX0cv0ILtaQuPv9bU2phiTi9fj5oDeOGvq5sF46hHYhDcIb3_ju9oF-bG45gg6DNWXNH3YV6umA-B" +
          "asejO0W0ir7r9IE7GPQPVtMpDWDVo1w-fRDS4BiSFOaOojHoY3POz087SDIGIC5kNmz6nOkQDb38urPVamMT1461iWUcjE\",\"dp\":" +
          "\"qYUEfSAKsFTVCTqVo0f9qC192BjadnXidzk2xa7etyjI3Q05ZsOHowlofnbpdzS9Q55VQ9vOAmzWF1SJndwT7kIgaBUY6T-rUfY_9eI" +
          "phx2CHhI-AgljYpF0K09T7KUV31YvMBN3NAUBiDh_7WRD8tLhAegQ5ytLbYGNqPcueW8\",\"dq\":\"EmLnd5WJRq9yE-D1YvlZ0NVq3" +
          "yjmVpfNLrKcqV7xu5q9rgvllLHzva3QSx7qM9znguF1xLR0zshdxFQTX7i3GgcOjiTUm_IyZ8sLiIXhQpVVTog0nUTXhnE0k5g5hJMTv9" +
          "Ey6mTMgqTB9dwE5S2DvNsuRGYONzP8gf2EdjTWm4E\",\"qi\":\"YMui-he-fz_wv-ZdV--r6j4Utdz9p4BtjtfEA1_XQ40U944EIBpu" +
          "ZToKgE9Fquqqz6E3oc_2cgr3NBEXMz2hdUgkM6s4jz-Mtc2PZRSVRQZq7RTnCBaahHr9mQhaEanoae69M79SvkcTGK_APnodFrfWZJfEU" +
          "PffK0izKMM5KTs\"}").eLiftET[IO]
        rsaJwk4096 <- decode[Id, AsymmetricJsonWebKey]("{\"kty\":\"RSA\",\"n\":\"oOtx-ZO3KSNr_Wy5VJjXUJOuZq70nyd4QWT" +
          "XsM4bQGqZlGPtMAqjxo-Qkw6WGubJxABtDxKUJBlmNgqieEFrFixV-_-DaujvoaXYi4C1T5a7WdIIYyEZmTztoeVnyWusYJBRpjONu4uM" +
          "IfT-flbkmQu9MFs_0FEApLrhiMkujXxOffmw8gBVE2dmSwU74IpC8VsaZBInjr6B0-LLCYuFaRHfF5Nnq2wV3Roo8m_rhH-yrnEf9fbao" +
          "ZH6rPTrBWc_thJq-X7qeFmHAyELCM_xlGSwnz2H8jPTRWJU4feTS7Ons71Ig0ot7NJF4GBHJ4HyeBjj3a2LQUA14kiDfDAkJntS3egVAI" +
          "w4No7We-pr5JdOPIZztwriZ2w_8aUDhqBNgXHuYAekQLj0qjRcwFoENy5pD-FsIXUeDO7agNbpbl-Wlgos2M97eaut359HPmZ7veLj0zh" +
          "K3Uy6nsT0SO7-JhrqEnALn-AxXhU0yN3AntwU_qhjrtgrxcSYVYGN5os1xvbBoKmtlQik_vWO5JoiRXpz2EtT9EUQcdY16M1eTjStOnlk" +
          "9BcFSvbNsHj_skEAtP_iCAdlQkkKYqzhCZSK1QCAp20_F2hlMlx-MS1dWgZjjf5MDebsTlu7c6IXxhAbM42m5EUQdpPp8dv0ValaaCU_g" +
          "L7_G0-gXlqM-Yl23K0\",\"e\":\"AQAB\",\"d\":\"EmxCJS-bJZOPlnjvEtdYtznhGpJnIR10sA_qfaxrBEnwAUQbcIeXTnE7PQrLd" +
          "pL7gHwIAFTBLwzVXdSD2z6qEuTKh0oucnvui1QgYYA_wbfhBRx9p1OvyZJnJkTMSAwStQ9wuZVnYZRNW8nfpPkvvLHSXAnmWWQcrb9TeM" +
          "SHlt0nY1bFwj71fn41ANu9iixqE5W5hMFrU_VNicOKOTKG-It6Pgm7Ma3zJtgK3g6gKRAxlbUP0qoLR7odt9VmXrz-V0ruglfcYiDlyx7" +
          "qU3zzDGkmq2Rw_vKd-nCShThB3cXYqkQ-XAGPFnDQXSrImqZO6x72X3ex3KuMP7bLjtk4Ghx3yFxRUNJAaQEKgMTvFNsybx7oCPTOXxAV" +
          "hxCeEuv1o1b4g6mCs9XVlUPVnZwt4fW-QHeenqeLe-Y3gsPEAkGdsZoEL0eQqjwVad-MdA0r3BHJQRjBp2YDujF5V8ypJeR6CE1ILlc2W" +
          "4DvhzgpGF3m2RUUqSXVj1aOCciZGAwtU-Lhgg4hDkv8ZV6nKE-O2FbI_126n41e-PeBoh8214RAJeAW82y3AAP3lwd38EfLIxt17rQ2bK" +
          "IDx4kJmgtW5a4LiAshvYN3SgqtyKvJSbDllLIy6OdXWlSv_ogcbeDnY3F5MNBfn6moGupsvOWkOH3zX6TxifBDjsebwMab8UE\",\"p\"" +
          ":\"9FQGthSnO6TSEFODI-NjyyqdWwWGDHueIjAKBB76hnc5XAojVJepmbnD3HrUm3ujqbA9uGygdTl88gHiv-nDxYkRL9foNmTdCrzIqq" +
          "xZnYfmHQjCbRXbc8oFd-bDRNLMZFX7TJbnaSugdgDNcVLTH8nd-qKH4VLdGnrTiQrq4FjEEDSdgwfzDbM9LrNxT_9KZlCsEj9eTqGJW5f" +
          "ugU2QvfVvdocnRKwMkg22rQ8Rt2IDexD3LSLcZwjF3yd1Bxm0VA1ks-Gc229NSyETGf45eNn9M6Uxb_jXM7hpdxAQyVh8Ua_bMzh6u5ED" +
          "giymigwgQx79eJswyzSeYmD99VwmHQ\",\"q\":\"qJtjOBXxIMQkD5I60PqbQ8l3ehIs3uXaOzMt8beyEzLfSH77fu-cZGkYLYtGnKuC" +
          "kt_Yv-gN6IQgBF9kE7Jic5FIITSnC2Qjem7BAmDV6-2f9xRSisNznR-tScsMMtIKVFm4Gr0rZpZICRNKSOZJ4EhL17JEqmUihw--9H1dj" +
          "C1K9Emgy9nJhgbUrWuJ_ShF2PZeUet_ABI6P11m3wUmCZScf3o4prqqJQcdjVTYXdSA6XfnzTilIDFCSlNJY4uAYZ5ZzOxQ2W3x1GXXFl" +
          "dmWv8wplylumWbY9jCCRUVWJiZqD0-cqBVVNuofVg0Po4usndlNGcpVp2HbWxJBJKL0Q\",\"dp\":\"XGDkxLVcYZ242vlobQpNsgRjy" +
          "IV3IIMg0BZPwy0fVfYAFv-ySgqp0ni9SECc4EjIIaGERJW1uXzJ9AqofB1bqvVfLTK6Fs7eEHA-guF1ZK18YN_t-ya3ebkZhjMXA4-cPh" +
          "eQU23_AvG-0r8M7lr9flhp-Ji5PYWCGb_0-SzKj5agUuxB3cgEqtppOJ4aKsAAllzMIn4ZHyvObnYsdHEqV9hTk4IYY8uVWSecOSSocyi" +
          "43jAU9NjocoCLqAsYIV4jo2AJAkY8c29KzywrN7m6ayoopP1Biu-QFnsUTTMi1a4CGzSdcWlaZk62_-H3-dwJ2rb96TrsIPi9Jb88Zie4" +
          "NQ\",\"dq\":\"dfX4zbV0NONlA0vgQHMEi8F5CHuMzwlqy_47h6BoQsxVsOe-VomXFhz84GhPp67KtK1NfL4CdQlzSPvgDXPBM2-SUkD" +
          "_GZYeyDqSaHKNV_mw7_FU6mZiDayq1TTsvOV8epUmm_Z7VdOQZGENmMEdMIAEJ80-AySsqmeWxoCrITZS-WRFzjj5p_5Bb28MZIR3kZqU" +
          "VKX4_XjDLa_QF_oHKa7CauF8nxF7llpLD6Url0HkSvMrxsV5qXMtGMj6UF26HRHna9ptmiE0jtANUkEliEZ_p_SrsiQCOjHdVvNcMtbYs" +
          "f7fIN0RtkPTtpYuPxHEk_G6aZY_Mq0VobWfxEYu8Q\",\"qi\":\"fZKGdPoeWTVRR5sbkP7eh_Kv8kYK4FDmHqwyt4e6Wgb-Sdnn2ZhM" +
          "I-4YzVMtSer167crPXBkuDbCCdXr2yBMT4XsyjFzKqr7ZqU-vQjRgYD7lDJtWF5KLLmxt8loM3tO0Ei1dg1dr8Vlc4U8JzIjpRmQxLqSk" +
          "qU9cpIPXcTzjOH8SYWi9IZhTLanwpUEYczfb2h0wkEVNY2zZrONkF7aj-fjkVxpkuDVDx3m6Kc7-5JgX7Kt4p7t-JLiym-yabf1yEeU3D" +
          "GS690Xf65XBQZKRUr4omMPPXm9_aTop7mtlZATqop7jeqeGSRuwaoilBZtJoidLxi2F2eUWVhASZg2Vg\"}").eLiftET[IO]
        // signed with the 2048 one
        jws <- JsonWebSignature.parse("eyJhbGciOiJSUzUxMiJ9.eyJjbGFpbSI6InZhbHVlIn0.Wp5B7mYIK-Pwx-3BQJvy8M6lOoUS1kof" +
          "MSC-eSWtY44NUwizjAmjwnLWPbdBgSFDdTtqRE8NQdFn6aHLURdtCR4LRSgJVkdE9M_ggbvLfB2nZ6CFGbg89AWZ2Uq-EQPIzXrg9QiK9" +
          "OeZjQyFgp1i89Eucy0Xc5bTYRCzLxfEbHWzFhacPFXm2RuZMSYbYJK2-6yDnfQGsyH6B50toCZSJI0e4SKF71U9EU78Y7PLTwyMcQLbgT" +
          "sxkv0o0AKyZYujWM_GqKx_m2qbfAioqrNBg1-XuGnmv5hxmqFTMFCYBeOXeltuaVcC9iRxIZOKBDxjdENO_pmomgMrdD730tz43Q"
        ).eLiftET[IO]
        rsaKey2048 <- EitherT(rsaJwk2048.toKey[IO]())
        primitives <- EitherT(JsonWebKeySet(rsaJwk2048, rsaJwk4096).verificationPrimitives[IO](jws))
        primitive <- EitherT(jws.checkWithPrimitives[IO](primitives))
      yield
        primitive.key.exists(_.equals(rsaKey2048))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with key ops in selector kinda random" in {
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet]("{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"verify\",\"nope\",\"whatever\"]" +
          ",\"x\":\"H78v6ZjjJPKmtrQNRECVQiGXFKOYFMHLG0q7SJd__5s\",\"y\":\"7-U3zo9sDyg7BCOoY3Yj_SSZdXuiTJnG1YvjTtqsrf" +
          "s\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"key_ops\":[\"verify\"],\"x\":\"S0ebOlceQ60hWjm1-Kuj5P3xH1t_NCSMf" +
          "umBG1ULM5M\",\"y\":\"l3dzIN8mJofWUtQT3jHf-c2jRViXcWam4tfsiyUp6RI\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"k" +
          "ey_ops\":[\"deriveBits\",\"unknown\"],\"x\":\"1O1K45F2hApgHgF6M1HCh7352uojDnXxcmiYdJuNBSo\",\"y\":\"MoIl5" +
          "LLxXIMPfBSUPJXKO8hyv6lCsHgmyc2GWeqi77I\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"uHo8t" +
          "p88587_RB07P3U2Ev7EZCqhpplFXfrOLyqnVwE\",\"y\":\"y9iW7nGBH_UkuRkn8YuQP8Lc5ftCqkzWDkxzBrof6PU\",\"crv\":\"" +
          "P-256\"},{\"kty\":\"EC\",\"use\":\"enc\",\"x\":\"vt4xF93UAJ733TuKEFN0RymIo5fW_iluEGL5s5cq098\",\"y\":\"AU" +
          "baLliBS6XE28Dx_sOO4M_Xc4rJH35ytrw_SRKZhRw\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"x\":\"JgKilKl8qjJ9-3Fnr_" +
          "l282-Z9N_hxBg54TGs_Gqn9yg\",\"y\":\"wVZH4ova35tsViVLmPY8NbZPnditgKO4JcD2zT6ePpg\",\"crv\":\"P-256\"}]}"
        ).eLiftET[IO]
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        primitives <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES256)), "", empty)))
      yield
        primitives.length == 3
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with key ops in selector" in {
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet]("{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"encrypt\"],\"x\":\"eBTzLIja4bP6" +
          "Q25Ns5NBfb1PGuT5qVqxtzhK0gmA2wY\",\"y\":\"ToPEAa1KCYkqZ9z0tOt3vzI8vbWXSBVPIau3h68-I9E\",\"crv\":\"P-256\"" +
          "},{\"kty\":\"EC\",\"key_ops\":[\"encrypt\"],\"x\":\"lziTuxjaY7mq4UcPocqLGGxDlz9NWKSmNWbFPQM1JW8KJdlgw7s0t" +
          "4xbjVBuPh-h\",\"y\":\"bmwU8zrsuM88wIGUod6DgBg-yP0aEdXpbB00cRVpCI1Wd8BnSShz0DNGnu5pl4qN\",\"crv\":\"P-384" +
          "\"},{\"kty\":\"EC\",\"key_ops\":[\"verify\"],\"x\":\"tZXiftlYcS8qfJvB0ZL7D2QnL2TX5FHwtVzYUn40ZMlqXp-jxb7S" +
          "owVTrevWTWP-\",\"y\":\"tJG_JYi8dVIa8pusu77OuiW1HXzB-s-q2uf55XXBRu10A2v8xOIO_80ZI7YtPPb4\",\"crv\":\"P-384" +
          "\"},{\"kty\":\"EC\",\"key_ops\":[\"verify\"],\"x\":\"gfcWFvzU0CrtEImwdjJTgoYKpwcFO5EIykj1Wx8wx_M\",\"y\":" +
          "\"9ilsfMCVn_FRyy1p20mZRyBuSTHnU1fss_TlbY8qo40\",\"crv\":\"P-256\"}]}\n").eLiftET[IO]
        thirdJwk <- Try(jwks.keys(2)).asError.eLiftET[IO]
        thirdKey <- EitherT(thirdJwk.toKey[IO]())
        fourthJwk <- Try(jwks.keys(3)).asError.eLiftET[IO]
        fourthKey <- EitherT(fourthJwk.toKey[IO]())
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        primitives1 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES256)), "", empty)))
        primitives2 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES384)), "", empty)))
      yield
        primitives1.length == 1 && primitives1.head.key.exists(_.equals(fourthKey)) &&
          primitives2.length == 1 && primitives2.head.key.exists(_.equals(thirdKey))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with use in selector" in {
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet]("{\"keys\":[{\"kty\":\"EC\",\"use\":\"enc\",\"x\":\"eBTzLIja4bP6Q25Ns5NBfb" +
          "1PGuT5qVqxtzhK0gmA2wY\",\"y\":\"ToPEAa1KCYkqZ9z0tOt3vzI8vbWXSBVPIau3h68-I9E\",\"crv\":\"P-256\"},{\"kty\"" +
          ":\"EC\",\"use\":\"enc\",\"x\":\"lziTuxjaY7mq4UcPocqLGGxDlz9NWKSmNWbFPQM1JW8KJdlgw7s0t4xbjVBuPh-h\",\"y\":" +
          "\"bmwU8zrsuM88wIGUod6DgBg-yP0aEdXpbB00cRVpCI1Wd8BnSShz0DNGnu5pl4qN\",\"crv\":\"P-384\"},{\"kty\":\"EC\"," +
          "\"use\":\"sig\",\"x\":\"tZXiftlYcS8qfJvB0ZL7D2QnL2TX5FHwtVzYUn40ZMlqXp-jxb7SowVTrevWTWP-\",\"y\":\"tJG_JY" +
          "i8dVIa8pusu77OuiW1HXzB-s-q2uf55XXBRu10A2v8xOIO_80ZI7YtPPb4\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"use\":" +
          "\"sig\",\"x\":\"gfcWFvzU0CrtEImwdjJTgoYKpwcFO5EIykj1Wx8wx_M\",\"y\":\"9ilsfMCVn_FRyy1p20mZRyBuSTHnU1fss_T" +
          "lbY8qo40\",\"crv\":\"P-256\"}]}\n").eLiftET[IO]
        thirdJwk <- Try(jwks.keys(2)).asError.eLiftET[IO]
        thirdKey <- EitherT(thirdJwk.toKey[IO]())
        fourthJwk <- Try(jwks.keys(3)).asError.eLiftET[IO]
        fourthKey <- EitherT(fourthJwk.toKey[IO]())
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        primitives1 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES256)), "", empty)))
        primitives2 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES384)), "", empty)))
      yield
        primitives1.length == 1 && primitives1.head.key.exists(_.equals(fourthKey)) &&
          primitives2.length == 1 && primitives2.head.key.exists(_.equals(thirdKey))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeySetForVerification" should "succeed with check it'll find secp256k1" in {
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet]("{\"keys\":[{\"kty\":\"EC\",\"x\":\"-_Z0BX1s-hINAcEVzWgTn0OgIAan_24g7ZFMkZ" +
          "LHYyY\",\"y\":\"L3t0vMmh28DymQsBYGTR9C_Y3jNASGV3M8_RCZrvnIY\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"x\":\"" +
          "78TF5FZ41_5bpVBdGv59Jd4Ip18zhr5uKCIhKRI8F_6Ha1kGzp4PGhDYOyZmDI7S\",\"y\":\"l2BKr3aZw_R7fet4HBmCg4Xwu-7Ecj" +
          "KhSstAn3OjGSY8y8jYQclgk8LX3p7oUlge\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"x\":\"U5X4zZGAOgWIQPfaofYOjQ_Q3" +
          "Hq13sYL6llaQh8tB78\",\"y\":\"WMsv-6d0eF3ql44gE5n1KCfyUU_QCizWOTR0IWowA00\",\"crv\":\"secp256k1\"},{\"kty" +
          "\":\"EC\",\"x\":\"AUgUpR1m-pbOs7KpiCHlS7k9EofjFDEpLI_-KZ6EhVznRswd3EACl2KPu4BrZbnxxPiSu-C-4gHwGOH5z8xWNC8" +
          "D\",\"y\":\"AbNMeensLTYgUZbcFyK7oNqW_skbF9yQwW5_I6SeBif80p-vUagvXkOATz7_go1dNJobdwA-Wt2FedAMzb7cJqJI\",\"" +
          "crv\":\"P-521\"}]}\n").eLiftET[IO]
        thirdJwk <- Try(jwks.keys(2)).asError.eLiftET[IO]
        thirdKey <- EitherT(thirdJwk.toKey[IO]())
        empty = Base64UrlNoPad.fromByteVector(ByteVector.empty)
        primitives1 <- EitherT(jwks.verificationPrimitives[IO](JsonWebSignature(JoseHeader(Some(ES256K)), "", empty)))
      yield
        primitives1.length == 1 && primitives1.head.key.exists(_.equals(thirdKey))
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebKeySetForVerificationFlatSpec
