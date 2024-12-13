package com.peknight.jose.jwt

import cats.Id
import org.scalatest.flatspec.AnyFlatSpec
import com.peknight.codec.circe.parser.decode

class JsonWebTokenClaimsFlatSpec extends AnyFlatSpec:
  "JsonWebTokenClaims" should "failed with get bad issuer" in {
    assert(decode[Id, JsonWebTokenClaims]("{\"iss\":{\"name\":\"value\"}}").isLeft)
  }
end JsonWebTokenClaimsFlatSpec
