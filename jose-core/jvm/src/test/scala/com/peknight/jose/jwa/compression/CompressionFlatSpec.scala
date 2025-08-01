package com.peknight.jose.jwa.compression

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asET
import com.peknight.jose.jwa.encryption.{`A128CBC-HS256`, dir, randomBytes}
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.AES
import org.scalatest.flatspec.AsyncFlatSpec

class CompressionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "Compression" should "succeed" in {
    val plaintext = "This should compress pretty good, it should, yes it should pretty good it should pretty good it " +
      "should it should it should it should pretty good it should pretty good it should pretty good it should pretty " +
      "good it should pretty good it should pretty good it should pretty good."
    val run =
      for
        keyBytes <- randomBytes[IO](32).asET
        key = AES.secretKeySpec(keyBytes)
        jweWithZip <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(dir), Some(`A128CBC-HS256`),
          Some(Deflate)), plaintext, key))
        jweWithZipCompact <- jweWithZip.compact.eLiftET[IO]
        jweWithZip <- JsonWebEncryption.parse(jweWithZipCompact).eLiftET[IO]
        decryptedPlaintextWithZip <- EitherT(jweWithZip.decryptString[IO](key))
        jweWithoutZip <- EitherT(JsonWebEncryption.encryptString[IO](JoseHeader(Some(dir), Some(`A128CBC-HS256`)),
          plaintext, key))
        jweWithoutZipCompact <- jweWithoutZip.compact.eLiftET[IO]
        jweWithoutZip <- JsonWebEncryption.parse(jweWithoutZipCompact).eLiftET[IO]
        decryptedPlaintextWithoutZip <- EitherT(jweWithoutZip.decryptString[IO](key))
      yield
        jweWithZipCompact.length < jweWithoutZipCompact.length && decryptedPlaintextWithZip == plaintext &&
          decryptedPlaintextWithoutZip == plaintext
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "Compression" should "failed with bad zip value consume" in {
    val cs = "eyJ6aXAiOiJiYWQiLCJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..ZZZ0nR5f80ikJtaPot4RpQ." +
      "BlDAYKzn9oLH1fhZcR60ZKye7UHslg7s0h7s1ecNZ5A1Df1pq2pBWUwdRKjJRxJAEFbDFoXTFYjV-cLCCE2Uxw.zasDvsZ3U4YkTDgIUchjiA"
    val run =
      for
        jwe <- JsonWebEncryption.parse(cs).eLiftET[IO]
        header <- jwe.getMergedHeader.eLiftET[IO]
      yield
        true
    run.value.asserting(value => assert(value.isLeft))
  }
end CompressionFlatSpec
