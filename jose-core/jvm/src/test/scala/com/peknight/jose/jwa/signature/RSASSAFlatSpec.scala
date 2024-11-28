package com.peknight.jose.jwa.signature

import cats.Id
import com.peknight.scodec.bits.ext.syntax.bigInt.toUnsignedBytes
import com.peknight.validation.std.either.typed
import cats.data.EitherT
import cats.effect.IO
import com.peknight.codec.circe.parser.decode
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.jose.jwk.{JsonWebKey, d, e, n}
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.RSA
import org.scalatest.flatspec.AsyncFlatSpec

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
        jws <- JsonWebSignature.parse(jwsCompact).asError.eLiftET[IO]
        _ <- EitherT(jws.check[IO](Some(publicKey)))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "RSASSA" should "succeed with sign example" in {
    val run =
      for
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        jws <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(RS256)),
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
end RSASSAFlatSpec
