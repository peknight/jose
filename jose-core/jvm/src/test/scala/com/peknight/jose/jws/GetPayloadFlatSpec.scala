package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.security.mac.Hmac
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class GetPayloadFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "GetPayload" should "succeed with get payload" in {
    val jwkJson = """{"kty":"oct","k":"Y7T0ygpIvYvz9kSVRod2tcGhekjiQh4t_AF7GE-v0o8"}"""
    val cs = "eyJhbGciOiJIUzI1NiJ9.VUExNTgyIHRvIFNGTyBmb3IgYSBOQVBQUyBGMkYgd29ya3Nob3AgaW4gUGFsbyBBbHRv.YjnCNkxrv86F" +
      "6GufxddTYS_4URo3kmLKrREquZSEKDo"
    val run =
      for
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        jws <- JsonWebSignature.parse(cs).asError.eLiftET[IO]
        payload <- jws.decodePayloadUtf8.eLiftET[IO]
        _ <- EitherT(jws.check[IO]().map(_.swap.asError))
        _ <- EitherT(jws.check[IO](Some(Hmac.secretKeySpec(ByteVector.fill(32)(0)))).map(_.swap.asError))
      yield
        payload.nonEmpty
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

end GetPayloadFlatSpec
