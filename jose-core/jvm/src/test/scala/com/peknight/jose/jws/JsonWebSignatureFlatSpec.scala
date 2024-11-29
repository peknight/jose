package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.encryption.randomBytes
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.security.mac.Hmac
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class JsonWebSignatureFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebSignature" should "succeed with changing new key" in {
    val run =
      for
        jwk <- decode[Id, OctetSequenceJsonWebKey]("""{"kty":"oct","k":"9el2Km2s5LHVQqUCWIdvwMsclQqQc6CwObMnCpCC8jY"}""")
          .eLiftET[IO]
        jws <- JsonWebSignature.parse("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A")
          .asError.eLiftET[IO]
        emptyKey <- EitherT(jws.verify[IO](Some(Hmac.secretKeySpec(ByteVector.fill(32)(0)))))
        key <- jwk.toKey.eLiftET[IO]
        rightKey <- EitherT(jws.verify[IO](Some(key)))
        bytes <- EitherT(randomBytes[IO](32).asError)
        randomKey <- EitherT(jws.verify[IO](Some(Hmac.secretKeySpec(bytes))))
      yield
        !emptyKey && rightKey && !randomKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebSignatureFlatSpec
