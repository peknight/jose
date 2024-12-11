package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.jose.syntax.x509Certificate.base64UrlThumbprint
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.jose.error.ThumbprintMismatch
import com.peknight.jose.jwa.signature.*
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.digest.{`SHA-1`, `SHA-256`}
import com.peknight.validation.std.either.{isTrue, typed}
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

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
        x509CertificateSHA256Thumbprint7 <- Base64UrlNoPad.fromString("Xm5kcmgZp3dZmZc_-K31CzStJl5pH3QjRp45D8uhinM")
          .eLiftET[IO]

        keys7 <- EitherT(jwks.filterForVerification[IO](JsonWebSignature(JoseHeader(Some(RS512),
          x509CertificateSHA256Thumbprint = Some(x509CertificateSHA256Thumbprint7)), "", empty)))

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
end JsonWebKeySetForVerificationFlatSpec
