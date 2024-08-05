package com.peknight.jose.jws

import cats.Id
import com.peknight.codec.base.Base64Url
import com.peknight.codec.syntax.encoder.asS
import com.peknight.jose.jwa.signature.HS256
import io.circe.Json
import org.scalatest.flatspec.AnyFlatSpec
import scodec.bits.ByteVector

class JsonWebSignatureFlatSpec extends AnyFlatSpec:
  "JsonWebSignature" should "succeed" in {
    val header = JsonWebSignatureHeader(`type` = Some("JWT"), algorithm = Some(HS256))
    val headerJsonString = header.asS[Id, Json].deepDropNullValues.noSpaces
    val headerBase64 = ByteVector.encodeUtf8(headerJsonString).map(Base64Url.fromByteVector)
    assert(true)
  }
end JsonWebSignatureFlatSpec
