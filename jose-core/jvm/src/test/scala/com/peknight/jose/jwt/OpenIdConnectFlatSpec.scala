package com.peknight.jose.jwt

import cats.Id
import cats.data.{EitherT, NonEmptyList}
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.applicative.*
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.collection.CollectionEmpty
import com.peknight.jose.jwe.DecryptionPrimitive
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.validation.std.either.isTrue
import org.scalatest.flatspec.AsyncFlatSpec

import java.time.Instant

class OpenIdConnectFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "OpenIdConnect" should "succeed with verify signed request object" in {
    // OpenID Connect Core 1.0 - draft 15
    // 5.1.  Passing a Request Object by Value has a JWS JWT with a JWK
    val requestObject = "eyJhbGciOiJSUzI1NiJ9.ew0KICJyZXNwb25zZV90eXBlIjogImNvZGUgaWRfdG9rZW4iLA0KICJjbGllbnRfaWQiOi" +
      "AiczZCaGRSa3F0MyIsDQogInJlZGlyZWN0X3VyaSI6ICJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYiIsDQogInNjb3BlIjogIm9wZW5" +
      "pZCIsDQogInN0YXRlIjogImFmMGlmanNsZGtqIiwNCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwNCiAibWF4X2FnZSI6IDg2NDAwLA0KICJj" +
      "bGFpbXMiOiANCiAgew0KICAgInVzZXJpbmZvIjogDQogICAgew0KICAgICAiZ2l2ZW5fbmFtZSI6IHsiZXNzZW50aWFsIjogdHJ1ZX0sDQogI" +
      "CAgICJuaWNrbmFtZSI6IG51bGwsDQogICAgICJlbWFpbCI6IHsiZXNzZW50aWFsIjogdHJ1ZX0sDQogICAgICJlbWFpbF92ZXJpZmllZCI6IH" +
      "siZXNzZW50aWFsIjogdHJ1ZX0sDQogICAgICJwaWN0dXJlIjogbnVsbA0KICAgIH0sDQogICAiaWRfdG9rZW4iOiANCiAgICB7DQogICAgICJ" +
      "nZW5kZXIiOiBudWxsLA0KICAgICAiYmlydGhkYXRlIjogeyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgImFjciI6IHsidmFsdWVzIjogWyIy" +
      "Il19DQogICAgfQ0KICB9DQp9.bOD4rUiQfzh4QPIs_f_R2GVBhNHcc1p2cQTgixB1tsYRs52xW4TO74USgb-nii3RPsLdfoPlsEbJLmtbxG8-" +
      "TQBHqGAyZxMDPWy3phjeRt9ApDRnLQrjYuvsCj6byu9TVaKX9r1KDFGT-HLqUNlUTpYtCyM2B2rLkWM08ufBq9JBCEzzaLRzjevYEPMaoLAOj" +
      "b8LPuYOYTBqshRMUxy4Z380-FJ2Lc7VSfSu6HcB2nLSjiKrrfI35xkRJsaSSmjasMYeDZarYCl7r4o17rFclk5KacYMYgAs-JYFkwab6Dd56Z" +
      "rAzakHt9cExMpg04lQIux56C-Qk6dAsB6W6W91AQ"
    val jwkJson = "{\"kty\":\"RSA\",\"n\":\"y9Lqv4fCp6Ei-u2-ZCKq83YvbFEk6JMs_pSj76eMkddWRuWX2aBKGHAtKlE5P7_vn__PCKZW" +
      "ePt3vGkB6ePgzAFu08NmKemwE5bQI0e6kIChtt_6KzT5OaaXDFI6qCLJmk51Cc4VYFaxgqevMncYrzaW_50mZ1yGSFIQzLYP8bijAHGVjdEFg" +
      "ZaZEN9lsn_GdWLaJpHrB3ROlS50E45wxrlg9xMncVb8qDPuXZarvghLL0HzOuYRadBJVoWZowDNTpKpk2RklZ7QaBO7XDv3uR7s_sf2g-bAjS" +
      "YxYUGsqkNA9b3xVW53am_UZZ3tZbFTIh557JICWKHlWj5uzeJXaw\",\"e\":\"AQAB\"}"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toKey[IO]())
        jws <- JsonWebSignature.parse(requestObject).eLiftET[IO]
        _ <- EitherT(jws.check[IO](Some(key)))
        (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](requestObject)(
          VerificationPrimitive.verificationKey(Some(key))
        )(
          DecryptionPrimitive.defaultDecryptionPrimitivesF
        ))
      yield
        jwtClaims.ext("redirect_uri").flatMap(_.asString).contains("https://client.example.org/cb")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "OpenIdConnect" should "succeed with verify id tokens" in {
    // OpenID Connect Core 1.0 - draft 15
    // Appendix A.  Authorization Examples has several singed ID Tokens and a JWK
    val idTokenA2 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlci5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyOD" +
      "k3NjEwMDEiLA0KICJhdWQiOiAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4cCI6IDEzMTEyODE5NzAsDQo" +
      "gImlhdCI6IDEzMTEyODA5NzAsDQogIm5hbWUiOiAiSmFuZSBEb2UiLA0KICJnaXZlbl9uYW1lIjogIkphbmUiLA0KICJmYW1pbHlfbmFtZSI6" +
      "ICJEb2UiLA0KICJnZW5kZXIiOiAiZmVtYWxlIiwNCiAiYmlydGhkYXRlIjogIjAwMDAtMTAtMzEiLA0KICJlbWFpbCI6ICJqYW5lZG9lQGV4Y" +
      "W1wbGUuY29tIiwNCiAicGljdHVyZSI6ICJodHRwOi8vZXhhbXBsZS5jb20vamFuZWRvZS9tZS5qcGciDQp9.Bgdr1pzosIrnnnpIekmJ7ooeD" +
      "bXuA2AkwfMf90Po2TrMcl3NQzUE_9dcr9r8VOuk4jZxNpV5kCu0RwqqF11-6pQ2KQx_ys2i0arLikdResxvJlZzSm_UG6-21s97IaXC97vbnT" +
      "CcpAkokSe8Uik6f8-U61zVmCBMJnpvnxEJllfV8fYldo8lWCqlOngScEbFQUh4fzRsH8O3Znr20UZib4V4mGZqYPtPDVGTeu8xkty1t0aK-wE" +
      "hbm6Hi-TQTi4kltJlw47McSVgF_8SswaGcW6Bf_954ir_ddi4Nexo9RBiWu4n3JMNcQvZU5xMPhu-EF-6_nJNotp-lbnBUyxTSg"
    val idTokenA3 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlci5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyOD" +
      "k3NjEwMDEiLA0KICJhdWQiOiAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4cCI6IDEzMTEyODE5NzAsDQo" +
      "gImlhdCI6IDEzMTEyODA5NzAsDQogImF0X2hhc2giOiAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSINCn0.g7UR4IDBNIjoPFV8exQCosUNVeh8" +
      "bNUTeL4wdQp-2WXIWnly0_4ZK0sh4A4uddfenzo4Cjh4wuPPrSw6lMeujYbGyzKspJrRYL3iiYWc2VQcl8RKdHPz_G-7yf5enut1YE8v7PhKu" +
      "cPJCRRoobMjqD73f1nJNwQ9KBrfh21Ggbx1p8hNqQeeLLXb9b63JD84hVOXwyHmmcVgvZskge-wExwnhIvv_cxTzxIXsSxcYlh3d9hnu0wdxP" +
      "ZOGjT0_nNZJxvdIwDD4cAT_LE5Ae447qB90ZF89Nmb0Oj2b1GdGVQEIr8-FXrHlyD827f0N_hLYPdZ73YK6p10qY9oRtMimg"
    val idTokenA4 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlci5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyOD" +
      "k3NjEwMDEiLA0KICJhdWQiOiAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4cCI6IDEzMTEyODE5NzAsDQo" +
      "gImlhdCI6IDEzMTEyODA5NzAsDQogImNfaGFzaCI6ICJMRGt0S2RvUWFrM1BrMGNuWHhDbHRBIg0KfQ.dAVXerlNOJ_tqMUysD_k1Q_bRXRJb" +
      "LkTOsCPVxpKUis5V6xMRvtjfRg8gUfPuAMYrKQMEqZZmL87Hxkv6cFKavb4ftBUrY2qUnrvqe_bNjVEz89QSdxGmdFwSTgFVGWkDf5dV5eIiR" +
      "xXfIkmlgCltPNocRAyvdNrsWC661rHz5F9MzBho2vgi5epUa_KAl6tK4ksgl68pjZqlBqsWfTbGEsWQXEfu664dJkdXMLEnsPUeQQLjMhLH7q" +
      "pZk2ry0nRx0sS1mRwOM_Q0Xmps0vOkNn284pMUpmWEAjqklWITgtVYXOzF4ilbmZK6ONpFyKCpnSkAYtTEuqz-m7MoLCD_A"
    val idTokenA6 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlci5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyOD" +
      "k3NjEwMDEiLA0KICJhdWQiOiAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4cCI6IDEzMTEyODE5NzAsDQo" +
      "gImlhdCI6IDEzMTEyODA5NzAsDQogImF0X2hhc2giOiAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSIsDQogImNfaGFzaCI6ICJMRGt0S2RvUWFr" +
      "M1BrMGNuWHhDbHRBIg0KfQ.JQthrBsOirujair9aD5gj1Yd5qEv0j4fhLgl8h3RaH3soYhwPOiN2Iy_yb7wMCO6I3bPoGJc3zCkpjgUtdB4O2" +
      "eEhFqXHdwnE4c0oVTaTHJi_PdV2ox9g-1ikDB0ckWk0f0SzBd7yM2RoYYxJCiGBQlsSSRQz6ehykonI3hLAhXFdpfbK-3_a3HBNKOv_9Mr_JJ" +
      "rz2pqSygk5IBNvwzf1ouVeM91KKvr7EdriKN8ysk68fctbFAga1p8rE3cfBOX7Acn4p9QSNpUx0i_x4WHktyKDvH_hLdUw91Fql_UOgMP_9h8" +
      "TYdkAjcq8n1tFzaO7kVaazlZ5SM32J7OSDgNSA"
    val jwkJson = "{\"kty\":\"RSA\",\"n\":\"zhEWTBJVTfcUeqnMzOQFMCEVQWOyOUZwP8LrBWh88tKrZyPGCvBkTDp-E2BzyHMQV4pK51Uy" +
      "s2YOwzL9se5THDWMda9rtsCJVcj1V7WaE7wPgl-kIIdWWf4o2g6ZszOy_Fp4q0nG3OTtDRCkBu2iEP21j82pRSRrkCBxnzaChflA7KZbI1n_y" +
      "hKtxyA7FdA480LaSVZyKApvrKiYhocACSwf0y6CQ-wkEi6mVXRJt1aBSywlLYA08ojp5hkZQ39eCM2k1EdXdhbar998Q9PZTwXA1cfvuGTZbD" +
      "WxEKLjMKVuKrT1Yvs-2NTXhZAW1KjFS_3UwLkDk-w4dVN-x5tDnw\",\"e\":\"AQAB\"}"

    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toKey[IO]())
        _ <- List(idTokenA2, idTokenA3, idTokenA4, idTokenA6).traverse { idToken =>
          for
            jws <- JsonWebSignature.parse(idToken).eLiftET[IO]
            _ <- EitherT(jws.check[IO](Some(key)))
            (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](idToken)(
              VerificationPrimitive.verificationKey(Some(key))
            )(
              DecryptionPrimitive.defaultDecryptionPrimitivesF
            ))
            _ <- jwtClaims.expectedIssuers("http://server.example.com").eLiftET[IO]
            _ <- jwtClaims.expectedAudiences("s6BhdRkqt3").eLiftET[IO]
            _ <- jwtClaims.requireSubject.eLiftET[IO]
            _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1311280978L)).eLiftET[IO]
            _ <- isTrue(jwtClaims.subject.contains("248289761001"), Error("subject not match")).eLiftET[IO]
          yield
            ()
        }
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "OpenIdConnect" should "succeed with verify id tokens with kid" in {
    // OpenID Connect Core 1.0 - draft 15
    // ** with my changes to have a kid per http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20131104/004310.html**
    // Appendix A.  Authorization Examples has several singed ID Tokens and a JWK
    val idTokenA2 = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwK" +
      "ICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxM" +
      "zExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6ICJKYW5lIiwKICJmYW1pbH" +
      "lfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJmZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6ICJqYW5lZG9" +
      "lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNn" +
      "spA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcipR2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w" +
      "3K-E7yM2macAAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOYu0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eE" +
      "GGN6DH5K6o33TcxkIjNrCD4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl6cQQWNiDpWOl_lxXjQEvQ"
    val idTokenA3 = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwK" +
      "ICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxM" +
      "zExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAiYXRfaGFzaCI6ICI3N1FtVVB0alBmeld0RjJBbnBLOVJRIgp9.F9gRev0Dt2tKcrBkH" +
      "y72cmRqnLdzw9FLCCSebV7mWs7o_sv2O5s6zMky2kmhHTVx9HmdvNnx9GaZ8XMYRFeYk8L5NZ7aYlA5W56nsG1iWOou_-gji0ibWIuuf4Owah" +
      "o3YSoi7EvsTuLFz6tq-dLyz0dKABMDsiCmJ5wqkPUDTE3QTXjzbUmOzUDli-gCh5QPuZAq0cNW3pf_2n4zpvTYtbmj12cVcxGIMZby7TMWESR" +
      "jQ9_o3jvhVNcCGcE0KAQXejhA1ocJhNEvQNqMFGlBb6_0RxxKjDZ-Oa329eGDidOvvp0h5hoES4a8IuGKS7NOcpp-aFwp0qVMDLI-Xnm-Pg"
    val idTokenA4 = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwK" +
      "ICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxM" +
      "zExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAiYXRfaGFzaCI6ICI3N1FtVVB0alBmeld0RjJBbnBLOVJRIgp9.F9gRev0Dt2tKcrBkH" +
      "y72cmRqnLdzw9FLCCSebV7mWs7o_sv2O5s6zMky2kmhHTVx9HmdvNnx9GaZ8XMYRFeYk8L5NZ7aYlA5W56nsG1iWOou_-gji0ibWIuuf4Owah" +
      "o3YSoi7EvsTuLFz6tq-dLyz0dKABMDsiCmJ5wqkPUDTE3QTXjzbUmOzUDli-gCh5QPuZAq0cNW3pf_2n4zpvTYtbmj12cVcxGIMZby7TMWESR" +
      "jQ9_o3jvhVNcCGcE0KAQXejhA1ocJhNEvQNqMFGlBb6_0RxxKjDZ-Oa329eGDidOvvp0h5hoES4a8IuGKS7NOcpp-aFwp0qVMDLI-Xnm-Pg"
    val idTokenA6 = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwK" +
      "ICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxM" +
      "zExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAiY19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEEiCn0.XW6uhdrkBgcGx6zVIr" +
      "CiROpWURs-4goO1sKA4m9jhJIImiGg5muPUcNegx6sSv43c5DSn37sxCRrDZZm4ZPBKKgtYASMcE20SDgvYJdJS0cyuFw7Ijp_7WnIjcrl6B5" +
      "cmoM6ylCvsLMwkoQAxVublMwH10oAxjzD6NEFsu9nipkszWhsPePf_rM4eMpkmCbTzume-fzZIi5VjdWGGEmzTg32h3jiex-r5WTHbj-u5HL7" +
      "u_KP3rmbdYNzlzd1xWRYTUs4E8nOTgzAUwvwXkIQhOh5TPcSMBYy6X3E7-_gr9Ue6n4ND7hTFhtjYs3cjNKIA08qm5cpVYFMFMG6PkhzLQ"
    val jwkJson = "{\"kty\":\"RSA\",\"kid\":\"1e9gdk7\",\"n\":\"w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajv" +
      "WE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TY" +
      "OfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWz" +
      "fvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ\",\"e\":\"AQAB\"}"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jwk.toKey[IO]())
        _ <- List(idTokenA2, idTokenA3, idTokenA4, idTokenA6).traverse { idToken =>
          for
            jws <- JsonWebSignature.parse(idToken).eLiftET[IO]
            _ <- EitherT(jws.check[IO](Some(key)))
            (jwtClaims, nested) <- EitherT(JsonWebToken.getClaims[IO](idToken)(
              (jws, configuration) => jws.getUnprotectedHeader
                .flatMap(header => header.keyID.filter(jwk.keyID.contains).toRight(CollectionEmpty.label("primitives")))
                .map(_ => NonEmptyList.one(VerificationPrimitive(Some(key), configuration)))
                .pure[IO]
            )(
              DecryptionPrimitive.defaultDecryptionPrimitivesF
            ))
            _ <- jwtClaims.expectedIssuers("http://server.example.com").eLiftET[IO]
            _ <- jwtClaims.expectedAudiences("s6BhdRkqt3").eLiftET[IO]
            _ <- jwtClaims.requireSubject.eLiftET[IO]
            _ <- jwtClaims.checkTime(Instant.ofEpochSecond(1311280978L)).eLiftET[IO]
            _ <- isTrue(jwtClaims.subject.contains("248289761001"), Error("subject not match")).eLiftET[IO]
          yield
            ()
        }
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }
end OpenIdConnectFlatSpec
