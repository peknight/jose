package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.RS256
import com.peknight.jose.jwk.{d, e, n}
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.RSA
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class PayloadVariationsFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "PayloadVariations" should "succeed with raw bytes as payload" in {
    val bytesIn = ByteVector(-98, 96, -6, 55, -118, -17, -128, 13, 126, 14, 90, -21, -91, -7, -50, -57, 37, 79, 10, 45,
      52, 77, 87, -24, -18, -94, -45, 100, -18, 110, -20, -23, -123, 120, 99, -43, 115, 126, 103, 0, -18, -43, 22, -76,
      -84, 127, -110, 7, 78, -109, 44, 81, 119, -73, -115, -10, 18, 27, -113, -104, 14, -50, -105, -41, -49, 25, 26,
      116, -37, -42, 75, -109, -30, -62, 117, -44, 100, -114, 43, -125, 123, 39, -79, -55, -111, -36, 86, 42, -55, 123,
      -16, -74, 119, 59, -68, -4, -119, -118, -101, -76)
    val run =
      for
        privateKey <- EitherT(RSA.privateKey[IO](n, d).asError)
        jws <- EitherT(JsonWebSignature.signBytes[IO](JoseHeader(Some(RS256)), bytesIn, Some(privateKey)))
        compact <- jws.compact.eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).asError.eLiftET[IO]
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        bytesOut <- parsedJws.decodePayload.eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(publicKey)))
      yield
        bytesIn === bytesOut
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end PayloadVariationsFlatSpec
