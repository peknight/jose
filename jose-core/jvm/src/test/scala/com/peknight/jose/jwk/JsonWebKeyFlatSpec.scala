package com.peknight.jose.jwk

import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  "JsonWebKey EC" should "succeed" in {

    IO.println("rua").asserting(_ => assert(true))
  }
end JsonWebKeyFlatSpec
