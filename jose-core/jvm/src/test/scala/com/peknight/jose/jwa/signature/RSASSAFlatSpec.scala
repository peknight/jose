package com.peknight.jose.jwa.signature

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.ecc.{`P-256`, `P-521`}
import com.peknight.jose.jwk.*
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jws.JsonWebSignatureTestOps.{testBadKeyOnVerify, testBasicRoundTrip}
import com.peknight.jose.jwx.JoseHeader
import com.peknight.scodec.bits.ext.syntax.bigInt.toUnsignedBytes
import com.peknight.security.Security
import com.peknight.security.bouncycastle.jce.provider.BouncyCastleProvider
import com.peknight.security.cipher.RSA
import com.peknight.security.mac.Hmac
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.{isTrue, typed}
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import java.security.Provider as JProvider

class RSASSAFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  // http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-39#appendix-A.2
  private val jwsCompact = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGx" +
    "lLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YK" +
    "t_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0G" +
    "arZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX" +
    "LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
  "RSASSA" should "succeed with verify example" in {
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        jws <- JsonWebSignature.parse(jwsCompact).eLiftET[IO]
        _ <- EitherT(jws.check[IO](Some(publicKey)))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "RSASSA" should "succeed with sign example" in {
    val run =
      for
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(RS256)),
          "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}", Some(privateKey)))
        compact <- jws.compact.eLiftET[IO]
      yield
        compact == jwsCompact
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSASSA" should "succeed with key 11 to 12" in {
    // draft 12 used a JWK encoding of the key where previously it was octet sequences
    // and this is just a sanity check that it didn't change and my stuff sees them as the same
    // may want to redo some of the ExampleRsaKeyFromJws to just use the JWK serialization at some point
    // if private key support is added
    val jwkJson = "{\"kty\":\"RSA\",\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qP" +
      "CJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z" +
      "5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
      "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\",\"e\":\"AQAB\",\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ul" +
      "we2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaY" +
      "LU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO" +
      "1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"}"
    val run =
      for
        jsonWebKey <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        key <- EitherT(jsonWebKey.toKey[IO]())
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        rsaJsonWebKey <- typed[RSAJsonWebKey](jsonWebKey).eLiftET[IO]
        privateExponent <- rsaJsonWebKey.privateExponent.toRight(OptionEmpty).eLiftET[IO]
        privateExponentBytes <- privateExponent.decode[Id].eLiftET[IO]
      yield
        key.equals(publicKey) && privateExponentBytes === d.toUnsignedBytes
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "RSASSA" should "succeed with PSS round trips" in {
    val run =
      for
        provider <- EitherT(BouncyCastleProvider[IO].asError)
        _ <- EitherT(Security.addProvider[IO](provider).asError)
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        _ <-
          val tests =
            for
              alg <- `RSASSA-PSS`.values
              useLegacyName <- List(true, false)
              provider <- List(None, Some(provider))
            yield
              makePssJwsRoundTrip(alg, useLegacyName, provider)
          tests.sequence
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  private def makePssJwsRoundTrip(alg: JWSAlgorithm, useLegacyName: Boolean = false,
                                  provider: Option[Provider | JProvider] = None): EitherT[IO, Error, Unit] =
    val payload = "stuff here"
    for
      privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
      publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
      jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(alg)), payload, Some(privateKey),
        useLegacyName = useLegacyName, provider = provider))
      compact <- jws.compact.eLiftET[IO]
      parsedJws <- JsonWebSignature.parse(compact).eLiftET[IO]
      _ <- EitherT(parsedJws.check[IO](Some(publicKey), useLegacyName = useLegacyName, provider = provider))
      parsedPayload <- parsedJws.decodePayloadString().eLiftET[IO]
      _ <- isTrue(parsedPayload == payload, Error("payload must equal")).eLiftET[IO]
    yield
      ()

  "RSASSA" should "succeed with PSS some verifies" in {
    val jwss = List(
      // created using BC provider and "SHAxxxwithRSAandMGF1" with a PSSParameterSpec
      "eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.KaRX4zjLPIoT0AAK2YZ9deKyE28pZnTBS-dOaANNxpdlDrc5El99xlOD18qbPpwZDSx0iGdRT" +
        "dm078LZRO6O6VRxOS9sFJl_iau-LDtHT5rPpk0BiJOH6uWE_Dr2qttdOlHaL9FwJdYJSi5Oy6BwkFulfjRMvC2i5g62FEJ4HndeIqKgCA5m" +
        "iwni6erjQKbN_A58_HA664uGKHziUkCzNJPQo7xcODFo1UMJflBYxMjAG6q5J-wzCX2usoWk5KrPBovEOJHAL5hw1lQJ6NV0NRBKB6ND1mY" +
        "ZiLzyvEIVoUYqa3C_sXaXTfjZ7jCR0EJUX7FjzaIHamnErZZpL8nZDQ",
      "eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.XDsnCIxKsZy_Te8nToIcRvCskGE5J7sUFpYE_MflcEIZ5NLgT9SBpmLvEl9IfsJyoMxk9yH4_" +
        "_F5Cvl3bjcBQ8UCk4yW-P8J8MFVanyeCwtjAtwJl1So-W_Zd3DG-QpKlVaak9xE_-glgv7yNAAaRMHRrqDr1fwUnqDA7rjwq4OY_4kZh5j0" +
        "Pesna6A0MAnQJusPEQUpjFN1DWzzS-f20TPoLlm-4CzXE60X8DRLs3EzeJA0SPWdOcYosikg_yZdu3HzDWL-8Cs81gbXLZLqsf2CaPakunR" +
        "ouOcnCSRkYhrcwv2FFxlnV29ivNWpLzjSrhplHu99d1R-xT2ZIFJ91w",
      "eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.FZqQotC88S8E6pB08NEfIvrdwimHQAQACUWC7eBJOfSkZa52i1R2nRfI4CmcG3lEzMuYKsmRE" +
        "VysoDGTJWX5_X49-8Yilnq4hNBG2BN1nXwD3agRHmDNw0Pz8GgpjmK-LMcNZxSPtnLq0KnFtq1miOogFgg3xjaI21MIC0hzaE8DCvz1X82d" +
        "Lm_oVapjx4UivARTruME0T_4pcLsZViTkAmsg0Uu_bMOv3VWQLc-sZAl7rRPUa_dWTcAuBToPOcuxK0b6ZiM2akkDuGjbmVHEJNaKmcjWNO" +
        "l0Gj6wJg5Q2R4wboKP6NxaIs2tpf1qaolVZ2COcnmGGl10kmmIVHKXw",

      // created using BC provider and "SHAxxxwithRSAandMGF1" without a PSSParameterSpec (that seems to end up using
      // defaults that are the same)// created using BC provider and "SHAxxxwithRSAandMGF1" without a PSSParameterSpec
      // (that seems to end up using defaults that are the same)
      "eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.WWqFutYS09AWi2K1KX-rix_yrwTgt2urJz1ZVVAHSzGLFio9WR_L6qockPFKnhmISWvN1FLmO" +
        "gOLBJv9YmlUobH0ktNEXg7B03chRAt9vMgvhilExYzA_scnlOI9ZRBoThZ9TS7GazLX-NoFL9w4imm1MQkFgknkUaKHJK62VNeQZTQXqubI" +
        "Gw28g2SkMPU-J03mW5wM-3yK3wNgzcW_3VJyDGdnNnkVMu4o1Za17zlzxJxCVHkBih2nLCqiPO7OPrSEnq5F6pw6V4PN1UGQz9aKRy_IgnE" +
        "vNxI6y8JDRDSWSf80rYHCvfbUVbrP7H-COWc_VpplgXY9_vnX6_GX0w",
      "eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.eOrEcpfGhsBuBjvwUQNp8KEyJiQuNbmRbYLTAnlCtkScUb7ZSBqe7mlDyaym8uOHHkedhuwz-" +
        "5BDlbWzkZ7ISgUNm2g6e3xS-nhVnOr8ttWQ7dpsQeSspxohKafZfg6rAcyYrsljf41hhQfVVv-PBNe5fxEq8DKC-h3xFil4LmZ5XEEeMSlA" +
        "o5tU8g-BsWRpVk7qhXIncRHFsCPPBjN7gu-OU-JHCLkNdkp9wW1MJuLXUduKnP1aXW7FZji7ZyzQYXvpVA5vUAdFY9Zz_cM0QppwiaPew66" +
        "D_LfaSKwzSMB55nAc6gvpDfP_D3iAlrT47ZBofvPjYQejKdN4WK1_Tg",
      "eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.e6twRBcgDBYw8vw_Lqn0w9v-MiD5Tr8ovCMvlezeUt829zvgP2_9oY-azvHr6f15B9w7ehLFJ" +
        "t4nbBUuOMt4IrsEDxAB3puLA7bsHJCfE-2vNC6QrkG3uPDqPRGPGSL30gDUAOL3y6WHsXuAckDJnEgtAQsLWHi8ctiDt_9-jfskL0uimEoW" +
        "hThsThjI9vKp0QuQO2Bw_c0Y7BcbTzNU1DP3FEtUJT-je0d7K8TrKaidzRRqOykvNbfcad6w29xg0PQYb7ImfWY7FxCIBUpFkHJT4HR4upJ" +
        "6aEVS9SojB-tAM9jqiW5OI9ABHQE0ZUYcbPdR1xKG3nGcCx36YVQy3Q",

      // created using SUN provider with Java 11 and "RSASSA-PSS"// created using SUN provider with Java 11 and
      // "RSASSA-PSS"
      "eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.dZsMbU_NTVxZcLVY4kXoWhwpFh9kCm67RdeiLLJ8Kq4EW8zCcjbWvqe-vc76ImLuJ5nFGUnGq" +
        "_g4VwDicDAiEODMyf7Bj2-FJ4X_HizvJcCoidb0vpkLl2cAoYiRBA0fpfQoMgs-H_ml9Ow6sQXGf13QWl0e_NxW3giVsiHimBR4Grkvj1u5" +
        "LVfdlY_-1R2P8D9DWOpL7nNtKCVdzz5fsKDK31u7uyKLwpGMfpqyWl0X7Q9tyS7saqwCx996NLvdW7sfSuAyzX_-Mig67Y4-ZIPQbgEjfEV" +
        "8cuMKSQdVmsYOJIc2AYnQRt1mA1WC3N7DhcZlUlEOdkatolPUD-NbDg",
      "eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.hmAy5kD5TNGKxzp_6_-pbD4fVVW-xpGDrlfG3h6wijtnTrjV8QtD_qZEru87NcxACZqqgmMQe" +
        "SuPIl20upseMNEvPWLX9xtUlgyEYUSo8AwO7ouD8oZNAhaqFoyTvoh7D9-CxBYsbpu9pcLFvPnBg5wT7mzadbgH94w8tCL7kT5C9rwWLcOd" +
        "WU-s_0wY1CRAxbgbZZEA6EDjJbQ4krGuJPF20Lir7ERqIWEeZ1f3SGg5FPCSE1geSL5x0ggEYKKeMqDyhWYfWEe0ZT6_a-TMge_JU8OWq3B" +
        "ckeHnGQJadRy_eI41cs4iESDehFygjhzWdEewcHfuxV_ozN5UhiZzCw",
      "eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.ImpuH6M3mrX0-qmALLT1oLTJY4cj9byPRbXF18QVL2Uz4ij5qkx1IWljqPcidhEtg5PqYqESA" +
        "l4Jh0kxPDBoVrGr9x5lwOKfGJUkLepi8o38UmgreW7OsCU9KZ3dX5G6s9dCPYX7lwRRBACxy_BFz9NNIBX2R2xx1GbrsQsiX8v4e2b8O3Ei" +
        "gfwnRmvnjsm1cH4CK6prb_CVy579qSiDQJ1Qc5bIBAgVEYR-El4zJ106OxOfB9b0RStQAJ_0FYtHXSqTs8IoS_PCAeroqf1Id08fby8b4gy" +
        "puB5o-n8FRBdfKaVTbLA04C3qmoj0uImKx5EHWOlLVAH2k5EirkredA"
    )
    val run =
      for
        provider <- EitherT(BouncyCastleProvider[IO].asError)
        _ <- EitherT(Security.addProvider[IO](provider).asError)
        _ <-
          val tests =
            for
              jws <- jwss
              useLegacyName <- List(true, false)
              provider <- List(None, Some(provider))
            yield
              verifyJwsWithStuffHere(jws, useLegacyName, provider)
          tests.sequence
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  def verifyJwsWithStuffHere(jwsCompact: String, useLegacyName: Boolean = false,
                             provider: Option[Provider | JProvider] = None): EitherT[IO, Error, Unit] =
    val payload = "stuff here"
    for
      publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
      jws <- JsonWebSignature.parse(jwsCompact).eLiftET[IO]
      _ <- EitherT(jws.check[IO](Some(publicKey), useLegacyName = useLegacyName, provider = provider))
      parsedPayload <- jws.decodePayloadString().eLiftET[IO]
      _ <- isTrue(parsedPayload == payload, Error("payload must equal")).eLiftET[IO]
    yield
      ()

  "RSASSA" should "succeed with RSASSA-PKCS1-v1_5 round trips" in {
    val run =
      for
        pair <- EitherT(RSA.keySizeGenerateKeyPair[IO](2048).asError)
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        _ <- List("PAYLOAD!!!", "PAYLOAD!!", "PAYLOAD!").zip(`RSASSA-PKCS1-v1_5`.values).traverse {
          case (payload, alg) => testBasicRoundTrip(payload, alg, pair.getPrivate, pair.getPublic, privateKey, publicKey)
        }
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "RSASSA" should "succeed with RSASSA-PKCS1-v1_5 bad keys" in {
    val cs256 = "eyJhbGciOiJSUzI1NiJ9.UEFZTE9BRCEhIQ.ln8y7TlxyR0jLemqdVybaWYmcS2nIseDEqKNJ1J-mM6TXRWjfFKsJr1kzBgh1nK" +
      "HbVT6q_cgSoPLsb-9WGvpUMkt7N0NxqT2Vffcz_2HMwKvWDJZSjbuj6_XHSJye7gqySHiI2gOggSaYyIqnua-_kOmVGmgncrzwm2YRPgwLXAl" +
      "9zB0GNul7lNGDvs193WbgOJ-rKGj515NBfqb7cV2VjQg7vsrnzIWT8FKcrQ5TYNXMrybzK5Q_1BNIxOVlrTsdh_pcUNiJvKKgC3_5PBHkhaJr" +
      "Jlxfwmi77YW8ezwXpFKdzbh8cKKzO0ZhamOOJns99HPPot4jr26JCERzBVF3g"
    val cs384 = "eyJhbGciOiJSUzM4NCJ9.UEFZTE9BRCEhIQ.E27QWhxodHU2vB-C3eKr4SQR8YF1jptmDrw7LRtQF1105bUk_WQqI8dCZcJDBsH" +
      "dJ11O7JEmnRPJLiZd50eFnzcvZsAN5gh7q2eNnxCPuXjH2MoyRlIt6-8aSs-Es0l66Sz4slyOGjqRBRBqHcr7bu6gjo7mBh3XzS8ORnu5zn9G" +
      "j5XWr3emX5vwTq66UCfkyf6a2aa4knmYbGW0JiELVWU4rU2UhY5NjhxDW4omlOGiLpNhaX3LAgvA5nvNLi8HFlhVG8-GO4malIjj6rFdpwpZX" +
      "m3G-sMbpWCcNyu3DUxRDKgjIWjX2SpGLqgXYZEMcAjmF2CA3tsxy43aUalMYQ"
    val cs512 = "eyJhbGciOiJSUzUxMiJ9.UEFZTE9BRCEhIQ.d7n7w-Ndg1-zRrAAQ3kgP_3vg70M5YcPS4eVrGTgD3UILRnMz5rBQh4k42yTVC5" +
      "3K-pmA6ZpphVtlC0lI7j2ViOM9ObC-dR_vOCN0_X7wo3D8qY5KJUDacMpDb_YkWtc5aUpaLilCe7770vNuOU6GK4hXkbTALJuug1V87QVn-xK" +
      "DHAGMx_b2UgkzybbnribIAeMoqsgg5P9hCSu63xd8OxagbMzPC46ovr5IvTAhIJuONYeGQaOSdOMFFvuZzsZVmdwTQfC9zv-oC3vIF3BcSd1y" +
      "_8b7CNlFw2NdIf0G3whEnrZgIYofKjZ3QkrIMRGzEF4H3u3KxVwdgpc1OhVSQ"
    val run =
      for
        pair <- EitherT(RSA.keySizeGenerateKeyPair[IO](1024).asError)
        rsaPrivateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        rsaPublicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        ec256PublicKey <- EitherT(`P-256`.publicKey[IO](x256, y256).asError)
        ec521PublicKey <- EitherT(`P-521`.publicKey[IO](x521, y521).asError)
        ec256PrivateKey <- EitherT(`P-256`.privateKey[IO](d256).asError)
        ec521PrivateKey <- EitherT(`P-521`.privateKey[IO](d521).asError)
        _ <-
          val tests =
            for
              cs <- List(cs256, cs384, cs512)
              key <- List(Some(pair.getPublic), Some(pair.getPrivate), Some(rsaPrivateKey), None,
                Some(Hmac.secretKeySpec(ByteVector.fill(2048)(0))), Some(ec256PublicKey), Some(ec521PublicKey),
                Some(ec256PrivateKey), Some(ec256PublicKey))
            yield
              testBadKeyOnVerify(cs, key)
          tests.sequence
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }
end RSASSAFlatSpec
