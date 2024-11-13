package com.peknight.jose.jwa.compression

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.encryption.{`A128CBC-HS256`, dir, randomBytes}
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwx.{JoseHeader, toBytes}
import com.peknight.security.cipher.AES
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class CompressionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "Compression" should "succeed" in {
    val plaintext = "This should compress pretty good, it should, yes it should pretty good it should pretty good it " +
      "should it should it should it should pretty good it should pretty good it should pretty good it should pretty " +
      "good it should pretty good it should pretty good it should pretty good."
    val run =
      for
        keyBytes <- EitherT(randomBytes[IO](32).asError)
        key = AES.secretKeySpec(keyBytes)
        plaintextBytes <- toBytes(plaintext).eLiftET[IO]
        jweWithZip <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(dir),
          Some(`A128CBC-HS256`), Some(Deflate))))
        jweWithZipCompact <- jweWithZip.compact.eLiftET[IO]
        jweWithZip <- JsonWebEncryption.parse(jweWithZipCompact).asError.eLiftET[IO]
        decryptedPlaintextWithZipBytes <- EitherT(jweWithZip.decrypt[IO](key))
        decryptedPlaintextWithZip <- decryptedPlaintextWithZipBytes.decodeUtf8.asError.eLiftET[IO]
        jweWithoutZip <- EitherT(JsonWebEncryption.encrypt[IO](key, plaintextBytes, JoseHeader(Some(dir),
          Some(`A128CBC-HS256`))))
        jweWithoutZipCompact <- jweWithoutZip.compact.eLiftET[IO]
        jweWithoutZip <- JsonWebEncryption.parse(jweWithoutZipCompact).asError.eLiftET[IO]
        decryptedPlaintextWithoutZipBytes <- EitherT(jweWithoutZip.decrypt[IO](key))
        decryptedPlaintextWithoutZip <- decryptedPlaintextWithoutZipBytes.decodeUtf8.asError.eLiftET[IO]
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
        jwe <- JsonWebEncryption.parse(cs).asError.eLiftET[IO]
        header <- jwe.getUnprotectedHeader.eLiftET[IO]
      yield
        true
    run.value.asserting(value => assert(value.isLeft))
  }
end CompressionFlatSpec
