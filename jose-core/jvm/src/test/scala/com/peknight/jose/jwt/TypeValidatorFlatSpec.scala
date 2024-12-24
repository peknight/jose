package com.peknight.jose.jwt

import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec

class TypeValidatorFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "TypeValidator" should "succeed with validate example plus jwt" in {
    val run =
      for
        expected <- List("application/example+jwt", "example+jwt", "EXAMPLE+JWT", "application/example+JWT")
        require <- List(true, false)
      yield
        JoseHeader(`type` = Some("nope+jwt")).expectedType(expected, require).isLeft &&
          JoseHeader(`type` = Some("application/nope+jwt")).expectedType(expected, require).isLeft &&
          JoseHeader(`type` = Some("nope+howaboutno")).expectedType(expected, require).isLeft &&
          JoseHeader(`type` = Some("application/*+jwt")).expectedType(expected, require).isLeft &&
          JoseHeader(`type` = Some("jwt+example")).expectedType(expected, require).isLeft &&
          JoseHeader(`type` = Some("application/example+jwt")).expectedType(expected, require).isRight &&
          JoseHeader(`type` = Some("example+jwt")).expectedType(expected, require).isRight &&
          JoseHeader(`type` = Some("application/EXAMPLE+JWT")).expectedType(expected, require).isRight &&
          JoseHeader(`type` = Some("application/example+JWT")).expectedType(expected, require).isRight &&
          JoseHeader(`type` = Some("example+JWT")).expectedType(expected, require).isRight &&
          JoseHeader(`type` = Some("Example+jwt")).expectedType(expected, require).isRight &&
          JoseHeader(`type` = Some("example+JWT")).expectedType(expected, require).isRight
    assert(run.forall(identity))
  }
end TypeValidatorFlatSpec
