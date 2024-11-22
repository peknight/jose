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
import com.peknight.security.syntax.ecParameterSpec.{privateKey, publicKey}
import org.scalatest.flatspec.AsyncFlatSpec

class DetachedContentFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "DetachedContent" should "succeed with some detached content" in {
    val payload = "Issue #48"
    val run =
      for
        privateKey <- EitherT(`P-256`.ecParameterSpec.privateKey[IO](d256).asError)
        jws <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(ES256)), payload, Some(privateKey)))
        detachedContentCompact <- jws.detachedContentCompact.eLiftET[IO]
        encodedPayload = jws.payload
        compact <- jws.compact.eLiftET[IO]
        publicKey <- EitherT(`P-256`.ecParameterSpec.publicKey[IO](x256, y256).asError)
        parsedDetachedJws <- JsonWebSignature.parse(detachedContentCompact, encodedPayload).asError.eLiftET[IO]
        _ <- EitherT(parsedDetachedJws.check[IO](Some(publicKey)))
        parsedDetachedPayload <- parsedDetachedJws.decodePayloadUtf8.eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).asError.eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(publicKey)))
        parsedPayload <- parsedJws.decodePayloadUtf8.eLiftET[IO]
        parsedPartJws <- JsonWebSignature.parse(detachedContentCompact).asError.eLiftET[IO]
        partVerify <- EitherT(parsedPartJws.verify[IO](Some(publicKey)))
      yield
        parsedDetachedPayload == payload && parsedPayload == payload && !partVerify
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end DetachedContentFlatSpec
