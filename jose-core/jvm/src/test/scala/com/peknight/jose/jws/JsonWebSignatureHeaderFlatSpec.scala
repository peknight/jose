package com.peknight.jose.jws

import com.peknight.jose.jwa.signature.HS256
import io.circe.parser.decode
import io.circe.syntax.*
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AnyFlatSpec

class JsonWebSignatureHeaderFlatSpec extends AnyFlatSpec:
  "JsonWebSignatureHeader" should "succeed" in {
    val header = JsonWebSignatureHeader(
      algorithm = Some(HS256),
      ext = Some(JsonObject("exp" -> Json.fromLong(1363284000)))
    )
    val json = header.asJson.deepDropNullValues.noSpaces
    val decoded = decode[JsonWebSignatureHeader](json)
    given CanEqual[JsonWebSignatureHeader, JsonWebSignatureHeader] = CanEqual.derived
    assert(decoded.exists(_ == header))
  }
end JsonWebSignatureHeaderFlatSpec
