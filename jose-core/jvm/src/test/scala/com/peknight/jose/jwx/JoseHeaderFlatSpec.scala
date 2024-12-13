package com.peknight.jose.jwx

import com.peknight.jose.jwa.signature.HS256
import io.circe.parser.decode
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AnyFlatSpec

class JoseHeaderFlatSpec extends AnyFlatSpec:
  "JoseHeader" should "succeed" in {
    val header = JoseHeader(
      algorithm = Some(HS256),
      ext = JsonObject("exp" -> Json.fromLong(1363284000))
    )
    val json = encodeToJson(header)
    val decoded = decode[JoseHeader](json)
    given CanEqual[JoseHeader, JoseHeader] = CanEqual.derived
    assert(decoded.exists(_ == header))
  }
end JoseHeaderFlatSpec
