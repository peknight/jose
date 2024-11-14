package com.peknight.jose.jwk

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.ecc.{`P-256`, `P-384`, `P-521`}
import com.peknight.validation.std.either.typed
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.interfaces.{ECPrivateKey, ECPublicKey}

class EllipticCurveJsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "EllipticCurveJsonWebKey" should "succeed with gen test" in {
    List(`P-256`, `P-384`, `P-521`).map { curve =>
      for
        keyPair <- EitherT(curve.generateKeyPair[IO]().asError)
        jwk <- JsonWebKey.fromKeyPair(keyPair).eLiftET[IO]
        publicKey <- EitherT(jwk.toPublicKey[IO]())
        _ <- typed[ECPublicKey](publicKey).eLiftET[IO]
        privateKey <- EitherT(jwk.toPrivateKey[IO]())
        _ <- typed[ECPrivateKey](privateKey).eLiftET[IO]
      yield
        ()
    }.sequence.value.asserting(value => assert(value.isRight))
  }
end EllipticCurveJsonWebKeyFlatSpec
