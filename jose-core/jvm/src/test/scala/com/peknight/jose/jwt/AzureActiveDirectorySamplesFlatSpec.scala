package com.peknight.jose.jwt

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.jose.jwk.JsonWebKeySet
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class AzureActiveDirectorySamplesFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebToken" should "succeed with consume azure id token v1" in {
    // ID token issued from
    // https://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/oauth2/authorize?
    // scope=openid&client_id=56c77428-2d91-48a0-93e6-ca9154965e51&response_type=code&redirect_uri=...etc
    val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ" +
      "19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiI1NmM3NzQyOC0yZDkxLTQ4YTAtOTNlNi1jYTkxNTQ5NjVlNTEiLCJpc3MiOiJod" +
      "HRwczovL3N0cy53aW5kb3dzLm5ldC8zMGFhMGU1OC03MTljLTQ0ZjAtYjViYi1lMTMxZjFmNjhhYjMvIiwiaWF0IjoxNDcwMDg2OTk3LCJuYm" +
      "YiOjE0NzAwODY5OTcsImV4cCI6MTQ3MDA5MDg5NywiYW1yIjpbInB3ZCJdLCJmYW1pbHlfbmFtZSI6IkNhbXBiZWxsIiwiZ2l2ZW5fbmFtZSI" +
      "6IkJyaWFuIiwiaXBhZGRyIjoiMjA1LjE2OS42OC4yMTgiLCJuYW1lIjoiQnJpYW4gQ2FtcGJlbGwiLCJvaWQiOiJmZDJkZGRlMy04Mjc1LTRi" +
      "MjgtOTlkMy0wMWIwNmY3MTg4NWEiLCJzdWIiOiJSNmZwYXZGcnpyWkY3VnVHM3c3RUNWREFJcmJmXzVPLVNCWTk4NkdwZ2FvIiwidGlkIjoiM" +
      "zBhYTBlNTgtNzE5Yy00NGYwLWI1YmItZTEzMWYxZjY4YWIzIiwidW5pcXVlX25hbWUiOiJ4QGNib2lkY3Rlc3R0ZXN0dGVzdC5vbm1pY3Jvc2" +
      "9mdC5jb20iLCJ1cG4iOiJ4QGNib2lkY3Rlc3R0ZXN0dGVzdC5vbm1pY3Jvc29mdC5jb20iLCJ2ZXIiOiIxLjAifQ.VWoMoC9Rx0DR394fQ9SK" +
      "Lv-6iUlADh9lcueJIYkH8jPuQhIMbvQJoUJ2TIg-ToFUJejgTRdI2BjokZa7FKtqT_7ZGfPwm9dvGCVsHPGkfvxwnvHMrLxbguqGZF941X1Hm" +
      "J_2sl39PK3wgvLv5Lp0mEtvsKxUTCwSR3xev1c5lF_XekEcJnKVW7zWKmUG25dy--hItIdyvrN09p8ibRW-jf4i8RPrFbduLpR-6nUyd7oBmq" +
      "KynwQc1_rPU52T1cKQsykLJn9e77_0FewDvB7ggb0gK6cf08MpNk6lfbwvtmpEJS77AgEYYg5LwxNrm7uiZBAai1QWOqtNzmEU5s5Mpg"
    // content from https://login.microsoftonline.com/common/discovery/keys on Aug 1, 2016
    val jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"MnC_VZcATfM5pOYiJHMba9goEKY\",\"x5t\":\"MnC_VZ" +
      "cATfM5pOYiJHMba9goEKY\",\"n\":\"vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq-RtwN1V" +
      "s_z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW_EW_P-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5y" +
      "Cw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3" +
      "-T-IAbsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGl" +
      "UXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMD" +
      "AwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQE" +
      "BBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNp" +
      "JMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKq" +
      "rIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNc" +
      "EbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlG" +
      "qYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeS" +
      "k4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmS" +
      "BtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\"]},{\"kty\":\"RSA\"," +
      "\"use\":\"sig\",\"kid\":\"YbRAQRYcE_motWVJKHrwLBbd_9s\",\"x5t\":\"YbRAQRYcE_motWVJKHrwLBbd_9s\",\"n\":\"vbcFr" +
      "j193Gm6zeo5e2_y54Jx49sIgScv-2JO-n6NxNqQaKVnMkHcz-S1j2FfpFngotwGMzZIKVCY1SK8SKZMFfRTU3wvToZITwf3W1Qq6n-h-abqpy" +
      "JTaqIcfhA0d6kEAM5NsQAKhfvw7fre1QicmU9LWVWUYAayLmiRX6o3tktJq6H58pUzTtx_D0Dprnx6z5sW-uiMipLXbrgYmOez7htokJVgDg8" +
      "w-yDFCxZNo7KVueUkLkxhNjYGkGfnt18s7ZW036WoTmdaQmW4CChf_o4TLE5VyGpYWm7I_-nV95BBvwlzokVVKzveKf3l5UU3c6PkGy-BB3E_" +
      "ChqFm6sPWw\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQfQ29fkGSsb1J8n2KueDFtDANBgkqhkiG9w0BAQsFADAtMSswKQ" +
      "YDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE2MDQxNzAwMDAwMFoXDTE4MDQxNzAwMDAwMFowLTErMCkGA1U" +
      "EAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL23Ba49fdxpus3q" +
      "OXtv8ueCcePbCIEnL/tiTvp+jcTakGilZzJB3M/ktY9hX6RZ4KLcBjM2SClQmNUivEimTBX0U1N8L06GSE8H91tUKup/ofmm6qciU2qiHH4QN" +
      "HepBADOTbEACoX78O363tUInJlPS1lVlGAGsi5okV+qN7ZLSauh+fKVM07cfw9A6a58es+bFvrojIqS1264GJjns+4baJCVYA4PMPsgxQsWTa" +
      "OylbnlJC5MYTY2BpBn57dfLO2VtN+lqE5nWkJluAgoX/6OEyxOVchqWFpuyP/p1feQQb8Jc6JFVSs73in95eVFN3Oj5BsvgQdxPwoahZurD1s" +
      "CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAe5RxtMLU2i4/vN1YacncR3GkOlbRv82rll9cd5mtVmokAw7kwbFBFNo2vIVkun+n+VdJf+QRzmHG" +
      "m3ABtKwz3DPr78y0qdVFA3h9P60hd3wqu2k5/Q8s9j1Kq3u9TIEoHlGJqNzjqO7khX6VcJ6BRLzoefBYavqoDSgJ3mkkYCNqTV2ZxDNks3obP" +
      "g4yUkh5flULH14TqlFIOhXbsd775aPuMT+/tyqcc6xohU5NyYA63KtWG1BLDuF4LEF84oNPcY9i0n6IphEGgz20H7YcLRNjU55pDbWGdjE4X8" +
      "ANb23kAc75RZn9EY4qYCiqeIAg3qEVKLnLUx0fNKMHmuedjg==\"]}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwks).eLiftET[IO]
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](idToken)(jwks.verificationPrimitives)(
          jwks.decryptionPrimitives
        ))
        _ <- jwtClaims.expectedIssuers("https://sts.windows.net/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/").eLiftET[IO]
        _ <- jwtClaims.acceptableAudiences("56c77428-2d91-48a0-93e6-ca9154965e51").eLiftET[IO]
        _ <- jwtClaims.expectedSubjects("R6fpavFrzrZF7VuG3w7ECVDAIrbf_5O-SBY986Gpgao").eLiftET[IO]
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1470086999)).eLiftET[IO]
      yield
        jwtClaims.ext("name").flatMap(_.asString).contains("Brian Campbell") &&
          jwtClaims.ext("ver").flatMap(_.asString).contains("1.0")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebToken" should "succeed with consume azure id token v2" in {
    // ID token issued from
    // https://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/oauth2/v2.0/authorize?
    // scope=openid+profile+email&client_id=6914484a-38ea-4a0b-801a-bb924cef5235&response_type=code...
    val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiI2" +
      "OTE0NDg0YS0zOGVhLTRhMGItODAxYS1iYjkyNGNlZjUyMzUiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vMzBhY" +
      "TBlNTgtNzE5Yy00NGYwLWI1YmItZTEzMWYxZjY4YWIzL3YyLjAiLCJpYXQiOjE0NzAxNDgzNjEsIm5iZiI6MTQ3MDE0ODM2MSwiZXhwIjoxND" +
      "cwMTUyMjYxLCJuYW1lIjoiQnJpYW4gQ2FtcGJlbGwiLCJvaWQiOiJmZDJkZGRlMy04Mjc1LTRiMjgtOTlkMy0wMWIwNmY3MTg4NWEiLCJwcmV" +
      "mZXJyZWRfdXNlcm5hbWUiOiJ4QGNib2lkY3Rlc3R0ZXN0dGVzdC5vbm1pY3Jvc29mdC5jb20iLCJzdWIiOiI2T2tzdlI3RzFwOHFDcVlCcDc2" +
      "aVJsaF9sRGJvUTdpV0V3cEwtRzhSUXRNIiwidGlkIjoiMzBhYTBlNTgtNzE5Yy00NGYwLWI1YmItZTEzMWYxZjY4YWIzIiwidmVyIjoiMi4wI" +
      "n0.dZ09eT52kUi0RwcGxuW5KZJhl_9ijMw2nVBRRiFv-CufR09EmkOaEEcHCUegUbepx3rzHYsrekXPT1Ys-c5_Thui3USkYE01oJfxcDGNi-" +
      "UVYrhGWVNVEUvfwBu_4LHLgV9DFQp1CJGQ859-_Bx_Xwn_xDGD6LnCZ0TecDRjM9wnWQQ__Tjj7OKzXx7PbWrskDspsh7juyVsihJIA7rXdNH" +
      "INtFCQDnG2JjO4p--5IiQNu4h2jXVYbjDJtRFFWwGQD2PDK3IBnsdVKCctR4KfbX-roRq_yIi69PnzjlsgHVvT7lamoYVWysRAkkZLySCgL_V" +
      "ZPiD4vp5HvKJiYNuZg"
    // content from https://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/discovery/v2.0/keys
    // on Aug 2, 2016
    val jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"MnC_VZcATfM5pOYiJHMba9goEKY\",\"x5t\":\"MnC_VZ" +
      "cATfM5pOYiJHMba9goEKY\",\"n\":\"vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq-RtwN1V" +
      "s_z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW_EW_P-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5y" +
      "Cw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3" +
      "-T-IAbsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGl" +
      "UXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMD" +
      "AwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQE" +
      "BBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNp" +
      "JMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKq" +
      "rIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNc" +
      "EbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlG" +
      "qYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeS" +
      "k4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmS" +
      "BtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\"],\"issuer\":\"https" +
      "://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/v2.0\"},{\"kty\":\"RSA\",\"use\":\"sig\",\"" +
      "kid\":\"YbRAQRYcE_motWVJKHrwLBbd_9s\",\"x5t\":\"YbRAQRYcE_motWVJKHrwLBbd_9s\",\"n\":\"vbcFrj193Gm6zeo5e2_y54J" +
      "x49sIgScv-2JO-n6NxNqQaKVnMkHcz-S1j2FfpFngotwGMzZIKVCY1SK8SKZMFfRTU3wvToZITwf3W1Qq6n-h-abqpyJTaqIcfhA0d6kEAM5N" +
      "sQAKhfvw7fre1QicmU9LWVWUYAayLmiRX6o3tktJq6H58pUzTtx_D0Dprnx6z5sW-uiMipLXbrgYmOez7htokJVgDg8w-yDFCxZNo7KVueUkL" +
      "kxhNjYGkGfnt18s7ZW036WoTmdaQmW4CChf_o4TLE5VyGpYWm7I_-nV95BBvwlzokVVKzveKf3l5UU3c6PkGy-BB3E_ChqFm6sPWw\",\"e\"" +
      ":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQfQ29fkGSsb1J8n2KueDFtDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50" +
      "cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE2MDQxNzAwMDAwMFoXDTE4MDQxNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuY" +
      "WNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL23Ba49fdxpus3qOXtv8ueCcePbCIEnL/" +
      "tiTvp+jcTakGilZzJB3M/ktY9hX6RZ4KLcBjM2SClQmNUivEimTBX0U1N8L06GSE8H91tUKup/ofmm6qciU2qiHH4QNHepBADOTbEACoX78O3" +
      "63tUInJlPS1lVlGAGsi5okV+qN7ZLSauh+fKVM07cfw9A6a58es+bFvrojIqS1264GJjns+4baJCVYA4PMPsgxQsWTaOylbnlJC5MYTY2BpBn" +
      "57dfLO2VtN+lqE5nWkJluAgoX/6OEyxOVchqWFpuyP/p1feQQb8Jc6JFVSs73in95eVFN3Oj5BsvgQdxPwoahZurD1sCAwEAATANBgkqhkiG9" +
      "w0BAQsFAAOCAQEAe5RxtMLU2i4/vN1YacncR3GkOlbRv82rll9cd5mtVmokAw7kwbFBFNo2vIVkun+n+VdJf+QRzmHGm3ABtKwz3DPr78y0qd" +
      "VFA3h9P60hd3wqu2k5/Q8s9j1Kq3u9TIEoHlGJqNzjqO7khX6VcJ6BRLzoefBYavqoDSgJ3mkkYCNqTV2ZxDNks3obPg4yUkh5flULH14TqlF" +
      "IOhXbsd775aPuMT+/tyqcc6xohU5NyYA63KtWG1BLDuF4LEF84oNPcY9i0n6IphEGgz20H7YcLRNjU55pDbWGdjE4X8ANb23kAc75RZn9EY4q" +
      "YCiqeIAg3qEVKLnLUx0fNKMHmuedjg==\"],\"issuer\":\"https://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e1" +
      "31f1f68ab3/v2.0\"}]}"

    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwks).eLiftET[IO]
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](idToken)(jwks.verificationPrimitives)(
          jwks.decryptionPrimitives
        ))
        _ <- jwtClaims.expectedIssuers("https://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/v2.0").eLiftET[IO]
        _ <- jwtClaims.acceptableAudiences("6914484a-38ea-4a0b-801a-bb924cef5235").eLiftET[IO]
        _ <- jwtClaims.expectedSubjects("6OksvR7G1p8qCqYBp76iRlh_lDboQ7iWEwpL-G8RQtM").eLiftET[IO]
        _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1470148369)).eLiftET[IO]
      yield
        jwtClaims.ext("name").flatMap(_.asString).contains("Brian Campbell") &&
          jwtClaims.ext("ver").flatMap(_.asString).contains("2.0")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end AzureActiveDirectorySamplesFlatSpec
