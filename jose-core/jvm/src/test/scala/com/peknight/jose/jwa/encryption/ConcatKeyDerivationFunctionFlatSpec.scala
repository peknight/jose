package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwx.stringEncodeToBytes
import com.peknight.security.digest.`SHA-256`
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class ConcatKeyDerivationFunctionFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "ConcatKeyDerivationFunction" should "succeed with get reps" in {
    IO.unit.asserting(_ => assert(
      ConcatKeyDerivationFunction.getReps(256, 256) == 1 &&
        ConcatKeyDerivationFunction.getReps(384, 256) == 2 &&
        ConcatKeyDerivationFunction.getReps(512, 256) == 2 &&
        ConcatKeyDerivationFunction.getReps(1024, 256) == 4 &&
        ConcatKeyDerivationFunction.getReps(1032, 256) == 5 &&
        ConcatKeyDerivationFunction.getReps(2048, 256) == 8 &&
        ConcatKeyDerivationFunction.getReps(2056, 256) == 9
    ))
  }

  "ConcatKeyDerivationFunction" should "succeed with get data length data" in {
    val apu = "QWxpY2U"
    val apv = "Qm9i"
    val run =
      for
        apuBase <- Base64UrlNoPad.fromString(apu).eLiftET[IO]
        apuBytes <- apuBase.decode[Id].eLiftET[IO]
        apuRes = ConcatKeyDerivationFunction.prependDataLength(Some(apuBytes))
        apvBase <- Base64UrlNoPad.fromString(apv).eLiftET[IO]
        apvBytes <- apvBase.decode[Id].eLiftET[IO]
        apvRes = ConcatKeyDerivationFunction.prependDataLength(Some(apvBytes))
      yield
        apuRes === ByteVector(0, 0, 0, 5, 65, 108, 105, 99, 101) &&
          apvRes === ByteVector(0, 0, 0, 3, 'B', 'o', 'b')
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "ConcatKeyDerivationFunction" should "succeed with kdf 1" in {
    // test values produced from implementation found at http://stackoverflow.com/questions/10879658
    val derivedKey = "pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA"
    val z = "Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0"
    testKdf(derivedKey, z, 64, `A256CBC-HS512`.identifier)
  }

  "ConcatKeyDerivationFunction" should "succeed with kdf 2" in {
    // test values produced from implementation found at http://stackoverflow.com/questions/10879658
    val derivedKey = "vphyobtvExGXF7TaOvAkx6CCjHQNYamP2ET8xkhTu-0"
    val z = "LfkHot2nGTVlmfxbgxQfMg"
    testKdf(derivedKey, z, 32, `A128CBC-HS256`.identifier)
  }

  "ConcatKeyDerivationFunction" should "succeed with kdf 3" in {
    // test values produced from implementation found at http://stackoverflow.com/questions/10879658
    val derivedKey = "yRbmmZJpxv3H1aq3FgzESa453frljIaeMz6pt5rQZ4Q5Hs-4RYoFRXFh_qBsbTjlsj8JxIYTWj-cp5LKtgi1fBRsf_5yTE" +
      "cLDv4pKH2fNxjbEOKuVVDWA1_Qv2IkEC0_QSi3lSSELcJaNX-hDG8occ7oQv-w8lg6lLJjg58kOes"
    val z = "KSDnQpf2iurUsAbcuI4YH-FKfk2gecN6cWHTYlBzrd8"
    testKdf(derivedKey, z, 128, "meh", Some(ByteVector(65, 108, 105, 99, 101)), Some(ByteVector(66, 111, 98)))
  }

  "ConcatKeyDerivationFunction" should "succeed with kdf 4" in {
    // test values produced from implementation found at http://stackoverflow.com/questions/10879658
    val derivedKey = "SNOvl6h5iSYWJ_EhlnvK8o6om9iyR8HkKMQtQYGkYKkVY0HFMleoUm-H6-kLz8sW"
    val z = "zp9Hot2noTVlmfxbkXqfn1"
    testKdf(derivedKey, z, 48, `A192CBC-HS384`.identifier)
  }

  def testKdf(derivedKey: String, z: String, cekLength: Int, algorithm: String, partyU: Option[ByteVector] = None,
              partyV: Option[ByteVector] = None): IO[Assertion] =
    val run =
      for
        zBase <- Base64UrlNoPad.fromString(z).eLiftET[IO]
        zBytes <- zBase.decode[Id].eLiftET[IO]
        algorithmId <- stringEncodeToBytes(algorithm).eLiftET[IO]
        kdfed <- EitherT(ConcatKeyDerivationFunction.kdf[IO](`SHA-256`, zBytes,
          ConcatKeyDerivationFunction.otherInfo(cekLength, Some(algorithmId), partyU, partyV), cekLength, None).asError)
        kdfBase = Base64UrlNoPad.fromByteVector(kdfed).value
      yield
        kdfBase == derivedKey
    run.value.asserting(value => assert(value.getOrElse(false)))

end ConcatKeyDerivationFunctionFlatSpec
