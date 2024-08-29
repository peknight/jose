package com.peknight.jose.jwe

import cats.Id
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.codec.base.Base64UrlNoPad
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class JsonWebEncryptionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebEncryption" should "succeed" in {
    val run =
      for
        _ <- IO.println(Base64UrlNoPad.unsafeFromString("eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0").decode[Id].flatMap(_.decodeUtf8).getOrElse(""))
      yield
        true
    run.asserting(assert)
  }
end JsonWebEncryptionFlatSpec
