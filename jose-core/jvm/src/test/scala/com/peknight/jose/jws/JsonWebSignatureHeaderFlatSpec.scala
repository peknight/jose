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
      ext = Some(JsonObject("abc" -> Json.fromString("123"), "9.as87123af,m." -> Json.fromBoolean(true)))
    )
    println(s"header=$header")
    val json = header.asJson.deepDropNullValues.noSpaces
    println(s"json=$json")
    val decoded = decode[JsonWebSignatureHeader](json)
    println(s"decoded=$decoded")
    given CanEqual[JsonWebSignatureHeader, JsonWebSignatureHeader] = CanEqual.derived
    assert(decoded.exists(_ == header))
  }
end JsonWebSignatureHeaderFlatSpec
