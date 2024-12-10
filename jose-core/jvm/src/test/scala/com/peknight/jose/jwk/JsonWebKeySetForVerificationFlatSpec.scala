package com.peknight.jose.jwk

import cats.Id
import cats.effect.IO
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.codec.circe.parser.decode
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebKeySetForVerificationFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKeySetForVerification" should "succeed with " in {
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
      yield
        true
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebKeySetForVerificationFlatSpec
