package com.peknight.jose.jwt

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKeySet
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class JwksVerificationPrimitivesFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JwksVerificationPrimitives" should "succeed with id token from pf" in {
    // JWKS from a PingFederate JWKS endpoint along with a couple ID Tokens (JWTs) it issued
    val jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhMDBrIn0.eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiUXhSYjF2Z2tpSE90M" +
      "lZoNVdST0pQUiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5MzM4MiwiZXhwIjoxNDIxMDkzOTgyLCJub2" +
      "5jZSI6Im5hbmFuYW5hIiwiYWNyIjoidXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQiLCJhdXRoX3RpbWU" +
      "iOjE0MjEwOTMzNzZ9.OlvyiduU_lZjcFHXchOzOptaBRt2XW_W2LATCPnfmi_mrfz5BsCvCGmTq6HCBBuOVF0BcbLA1h4ls3naPVu4YeWc1jk" +
      "KFmlu5UwAdHP3fdUvAQdByyXDAxFgYIwl06EF-qpEX7r5_1D0OnrReq55n_SA-iqRync2nn5ZhkRoEj77E5yMFG93yRp4IP-WNZW3mZjkFPnS" +
      "CEHfRU0IBURfWkPzSkt5bKx8Vr-Oc1I5hFUyKyap8Ky17q_PoF-bHZG7MZ8B5Q5RvweVbdudain_yH3VAujDtqN_gu-7m1Vt6WdQpFIOGsVSp" +
      "CK0-wtV3MvXzSKLk-5qwdVSI4GH5K_Q9g"
    val jwt2 = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjhhMDBsIn0.eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiRmUwZ1h1UGpmcHox" +
      "SHEzdzRaaUZIQiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5Mzg1OSwiZXhwIjoxNDIxMDk0NDU5LCJub" +
      "25jZSI6ImZmcyIsImFjciI6InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkIiwiYXV0aF90aW1lIjoxND" +
      "IxMDkzMzc2fQ.gzJQZRErEHI_v6z6dZboTPzL7p9_wXrMJIWnYZFEENgq3E1InbrZuQM3wB-mJ5r33kwMibJY7Qi4y-jvk0IYqQ"
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
    val badJwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjhhMTBsIn0.eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiRmUwZ1h1UGpmcH" +
      "oxSHEzdzRaaUZIQiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5Mzg1OSwiZXhwIjoxNDIxMDk0NDU5LCJ" +
      "ub25jZSI6ImZmcyIsImFjciI6InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkIiwiYXV0aF90aW1lIjox" +
      "NDIxMDkzMzc2fQ.gzJQZRErEHI_v6z6dZboTPzL7p9_wXrMJIWnYZFEENgq3E1InbrZuQM3wB-mJ5r33kwMibJY7Qi4y-jvk0IYqQ"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        _ <- List(jwt, jwt2).traverse(jwt => testIdTokenFromPf(jwks, jwt))
        _ <- EitherT(testIdTokenFromPf(jwks, badJwt).value.map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  private def testIdTokenFromPf(jwks: JsonWebKeySet, jwt: String): EitherT[IO, Error, Unit] =
    for
      (jwtClaims, _) <- EitherT(JsonWebToken.getClaims[IO](jwt)(jwks.verificationPrimitives)(jwks.decryptionPrimitives))
      _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1421093387L)).eLiftET[IO]
      _ <- jwtClaims.expectedAudiences("a").eLiftET[IO]
      _ <- jwtClaims.expectedIssuers("https://localhost:9031").eLiftET[IO]
      _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      _ <- jwtClaims.requireJwtID.eLiftET[IO]
      _ <- jwtClaims.requireSubject.eLiftET[IO]
      _ <- jwtClaims.expectedSubjects("hailie").eLiftET[IO]
    yield
      ()

  "JwksVerificationPrimitives" should "succeed with some Hmac ones" in {
    val json = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"uno\",\"k\":\"i-41ccx6-7rPpCK0-i0Hi3K-jcDjt8V0aF9aWY8081d1i2c3" +
      "3pzq5H5eR_JbwmAojgUl727gGoKz7COz9cjic1\"},{\"kty\":\"oct\",\"kid\":\"two\",\"k\":\"-v_lp7B__xRr-a90cIJqpNCo7u" +
      "6cY2o9Lz6-P--_01j0aF9d8bcKdrPpCK0-i0Hi3K-jcDjt8V0aF9aWY8081d\"},{\"kty\":\"oct\",\"kid\":\"trois\",\"k\":\"i-" +
      "41ccx6-7rPpCK0-i0Hi3K-jcDjt89Lz6-c_1_01ji-41ccx6-7rPpCK0-i0HiV0aF9d8bcKic10_aWY8081d\"}]}"
    val jwtWithTrios = "eyJhbGciOiJIUzUxMiIsImtpZCI6InRyb2lzIn0.eyJpc3MiOiJGUk9NIiwiYXVkIjoiVE8iLCJleHAiOjE0MjQyMTgy" +
      "MDUsInN1YiI6IkFCT1VUIn0.FtkwFqyO7nH6_FNBa-1kMGS2yx8Qabi9kQJMW2jbFWhFHYrM3VTlFIUw1Qc6znJSzLnfveix3Hi5ukc6EgIvVg"
    val jwtWithUno = "eyJhbGciOiJIUzUxMiIsImtpZCI6InVubyJ9.eyJpc3MiOiJGUk9NIiwiYXVkIjoiVE8iLCJleHAiOjE0MjQyMTg0MzYsI" +
      "nN1YiI6IkFCT1VUIn0.pJIcOeLWixUfePKf2ob4Piac6NByJUFlaZ5dXPoVVS1_NHIZr_9oLpFCOAe8HSqc47yO_d3bQ6mOExh1MXA6nQ"
    val jwtWithNope = "eyJhbGciOiJIUzUxMiIsImtpZCI6Im5vcGUifQ.eyJpc3MiOiJGUk9NIiwiYXVkIjoiVE8iLCJleHAiOjE0MjQyMTg2Nz" +
      "ksInN1YiI6IkFCT1VUIn0.lZOnt-l4wIUl667laxBjZgyTZsebfitsKT1yBrEQ-DognQiqEafQaVrFTaV3dJrZDvgDqAKL9FzxOHfdBg8NXw"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](json).eLiftET[IO]
        _ <- List(jwtWithTrios, jwtWithUno).traverse(jwt => testSomeHmacOnes(jwks, jwt))
        _ <- EitherT(testIdTokenFromPf(jwks, jwtWithNope).value.map(_.swap.asError))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  private def testSomeHmacOnes(jwks: JsonWebKeySet, jwt: String): EitherT[IO, Error, Unit] =
    for
      (jwtClaims, _) <- EitherT(JsonWebToken.getClaims[IO](jwt)(jwks.verificationPrimitives)(jwks.decryptionPrimitives))
      _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1424218020L)).eLiftET[IO]
      _ <- jwtClaims.expectedAudiences("TO").eLiftET[IO]
      _ <- jwtClaims.expectedIssuers("FROM").eLiftET[IO]
      _ <- jwtClaims.requireExpirationTime.eLiftET[IO]
      _ <- jwtClaims.requireSubject.eLiftET[IO]
      _ <- jwtClaims.expectedSubjects("ABOUT").eLiftET[IO]
    yield
      ()

  "JwksVerificationPrimitives" should "succeed with disambiguate with signature check option" in {
    val with1stEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIj" +
      "oidGhlIGlzc3VlciJ9.04tBvYG5QeY8lniGnkZNHMW8b0OPCN6XHuK9g8fsOz8uA_r0Yk-biMkWG7ltOMCFSiiPvEu7jNWfWbk0v-hWOg"
    val with2ndEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIj" +
      "oidGhlIGlzc3VlciJ9.uIRIFrhftV39qJNOdaL8LwrK1prIJIHsP7Gn6jJAVbE2Mx4IkwGzBXDLKMulM1IvKElmSyK_KBg8afywcxoApA"
    val with3rdEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIj" +
      "oidGhlIGlzc3VlciJ9.21eYfC_ZNf1FQ1Dtvj4rUiM9jYPgf1zJfeE_b2fclgu36KAN141ICqVjNxQqlK_7Wbct_FDxgyHvej_LEigb2Q"
    val with1stRsa = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzI" +
      "joidGhlIGlzc3VlciJ9.aECOQefwSdjN1Sj7LWRBV3m1uuHOFDL02nFxMWifACMELrdYZ2i9W_c6Co0SQoJ5HUE0otA8b2mXQBxJ-azetXT4Y" +
      "iJYBpNbKk_H52KOUWvLoOYNwrTKylWjoTprAQpCr9KQWvjn3xrCoers4N63iCC1D9mKOCrUWFzDy--inXDj-5VlLWfCUhu8fjx_lotgUYQVD0" +
      "3Rm06P3OWGz5G_oksJ7VpxDDRAYt7zROgmjFDpSWmAtNEKoAlRTeKnZZSN0R71gznBsofs-jJ8zF0QcFOuAfqHVaDWnKwqS0aduZXm0s7rH61" +
      "e4OwtQdTtFZqCPldUxlfC7uzvLhxgXrdLew"
    val jwsWith2ndRsa = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaX" +
      "NzIjoidGhlIGlzc3VlciJ9.pgBu9S8g7MC2BN9YNlWD9JhjzWbQVjqpmErW4hMFncKD8bUidIbMBJSI3URXvnMJrLrAC5eB2gb6DccF_txQaq" +
      "X1X81JbTSdQ44_P1W-1uIIkfIXUvM6OXv48W-CPm8xGuetQ1ayHgU_1ljtdkbdUHZ6irgaeIrFMgZX0Jdb9Eydnfhwvno2oGk3y6ruq2KgKAB" +
      "IdzgvJXfwdOFGn1z0CxwQSVDkFRLsMsBljTwfTd0v3G8OXT8WRMZMGVyAgtKVu3XJyrPNntVqrzdgQQma6S06Y9J9V9t0AlgEAn2B4TqMxYcu" +
      "1Tjr7bBL_v83zEXhbdcFBYLfJg-LY5wE6rA-dA"
    val withUnknownEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTEyNywiYXVkIjoidGhlIGF1ZGllbmNlIiwiaX" +
      "NzIjoidGhlIGlzc3VlciJ9.UE4B0IVPRip-3TDKhNAadCuj_Bf5PlEAn9K94Zd7mP25WNZwxDbQpDElZTZSp-3ngPqQyPGj27emYRHhOnFSAQ"
    val with384EC = "eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTIzMSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIj" +
      "oidGhlIGlzc3VlciJ9.NyRtG_eFmMLQ0XkW5kvdSpzYsm6P5M3U8EBFKIhD-jw8E7FOYw9PZ3_o1PWuLWH3XeArZMW7-bAIVxo2bHqJsSUtB6" +
      "Tf0NWPtCpUF2c1vbuRXEXkGrCUmc4sKyOBjimC"
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
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        _ <- List(with1stEC, with2ndEC, with3rdEC, with1stRsa, jwsWith2ndRsa).traverse(jwt =>
          testDisambiguateWithSignatureCheckOption(jwks, jwt))
        _ <- List(withUnknownEC, with384EC).traverse(jwt => EitherT(testDisambiguateWithSignatureCheckOption(jwks, jwt)
          .value.map(_.swap.asError)))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  private def testDisambiguateWithSignatureCheckOption(jwks: JsonWebKeySet, jwt: String): EitherT[IO, Error, Unit] =
    for
      (jwtClaims, _) <- EitherT(JsonWebToken.getClaims[IO](jwt)(jwks.verificationPrimitives)(jwks.decryptionPrimitives))
      _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1494437740L)).eLiftET[IO]
      _ <- jwtClaims.expectedAudiences("the audience").eLiftET[IO]
      _ <- jwtClaims.expectedIssuers("the issuer").eLiftET[IO]
      _ <- jwtClaims.expectedSubjects("me").eLiftET[IO]
    yield
      ()

end JwksVerificationPrimitivesFlatSpec
