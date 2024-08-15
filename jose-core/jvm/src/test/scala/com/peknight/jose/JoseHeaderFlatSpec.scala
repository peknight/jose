package com.peknight.jose

import com.peknight.jose.jwa.signature.HS256
import com.peknight.jose.jwx.JoseHeader
import io.circe.parser.decode
import io.circe.syntax.*
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AnyFlatSpec

class JoseHeaderFlatSpec extends AnyFlatSpec:
  "JoseHeader" should "succeed" in {
    val header = JoseHeader(
      algorithm = Some(HS256),
      ext = Some(JsonObject("exp" -> Json.fromLong(1363284000)))
    )
    val json = header.asJson.deepDropNullValues.noSpaces
    val decoded = decode[JoseHeader](json)
    given CanEqual[JoseHeader, JoseHeader] = CanEqual.derived
    assert(decoded.exists(_ == header))
  }
end JoseHeaderFlatSpec
