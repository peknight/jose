package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.ecc.`P-256`
import com.peknight.jose.jwa.signature.ES256
import com.peknight.jose.jwk.{d256, x256, y256}
import com.peknight.jose.jwx.JoseHeader
import org.scalatest.flatspec.AsyncFlatSpec

class DetachedContentFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "DetachedContent" should "succeed with some detached content" in {
    val payload = "Issue #48"
    val run =
      for
        privateKey <- EitherT(`P-256`.privateKey[IO](d256).asError)
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(ES256)), payload, Some(privateKey)))
        detachedContentCompact <- jws.detachedContentCompact.eLiftET[IO]
        encodedPayload = jws.payload
        compact <- jws.compact.eLiftET[IO]
        publicKey <- EitherT(`P-256`.publicKey[IO](x256, y256).asError)
        parsedDetachedJws <- JsonWebSignature.parse(detachedContentCompact, encodedPayload).eLiftET[IO]
        _ <- EitherT(parsedDetachedJws.check[IO](Some(publicKey)))
        parsedDetachedPayload <- parsedDetachedJws.decodePayloadString().eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(publicKey)))
        parsedPayload <- parsedJws.decodePayloadString().eLiftET[IO]
        parsedPartJws <- JsonWebSignature.parse(detachedContentCompact).eLiftET[IO]
        partVerify <- EitherT(parsedPartJws.verify[IO](Some(publicKey)))
      yield
        parsedDetachedPayload == payload && parsedPayload == payload && !partVerify
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end DetachedContentFlatSpec
