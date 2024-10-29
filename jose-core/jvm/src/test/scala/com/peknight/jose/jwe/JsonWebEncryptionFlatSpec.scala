package com.peknight.jose.jwe

import cats.Id
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.jwa.encryption.{RSA1_5, `RSA-OAEP-256`, `RSA-OAEP`}
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebEncryptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebEncryption" should "succeed" in {
    val run =
      for
        _ <- IO.println(Base64UrlNoPad.unsafeFromString("eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0").decode[Id].flatMap(_.decodeUtf8).getOrElse(""))
        _ <- IO.println(`RSA-OAEP-256`.transformation)
        _ <- IO.println(RSA1_5.transformation)
        _ <- IO.println(`RSA-OAEP`.transformation)
      yield
        true
    run.asserting(assert)
  }
end JsonWebEncryptionFlatSpec
