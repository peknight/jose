package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.scodec.bits.ext.syntax.byteVector.{leftHalf, rightHalf}
import com.peknight.security.signature.ECDSA.{convertConcatenatedToDER, convertDERToConcatenated}
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class ECDSAFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "ECDSA" should "succeed with encoding decoding" in {
    val rBytes = ByteVector(14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249,
      124, 126, 23, 129, 154, 195, 22, 158, 166, 101)
    val sBytes = ByteVector(197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197,
      242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213)
    val capacity = 64
    val concatedBytes = rBytes ++ sBytes
    val either =
      for
        derEncoded <- convertConcatenatedToDER(concatedBytes)
        backToConcated <- convertDERToConcatenated(derEncoded, capacity)
      yield
        !(derEncoded === concatedBytes) && concatedBytes === backToConcated
    IO.unit.asserting(_ => assert(either.getOrElse(false)))
  }

  "ECDSA" should "succeed with simple concatenation with length" in {
    val noPad = ByteVector(1, 2)
    val outputLength = 16
    val either =
      for
        der <- convertConcatenatedToDER(noPad)
        concatenated <- convertDERToConcatenated(der, outputLength)
      yield
        outputLength == concatenated.length && concatenated(7) == noPad(0) && concatenated(15) == noPad(1)
    IO.unit.asserting(_ => assert(either.getOrElse(false)))
  }

  "ECDSA" should "succeed with simple concatenation with diff lengths" in {
    val a = ByteVector(0, 0, 0, 0, 1, 1, 1, 1)
    val b = ByteVector(2, 2, 2, 2, 2, 2, 2, 2)
    val outputLength = 16
    val either =
      for
        der <- convertConcatenatedToDER(a ++ b)
        concatenated <- convertDERToConcatenated(der, outputLength)
      yield
        val first = concatenated.leftHalf
        val second = concatenated.rightHalf
        outputLength == concatenated.length && a === first && b === second
    IO.unit.asserting(_ => assert(either.getOrElse(false)))
  }

  "ECDSA" should "succeed with simple concatenation with very diff lengths" in {
    val a = ByteVector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    val b = ByteVector(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2)
    val outputLength = 32
    val either =
      for
        der <- convertConcatenatedToDER(a ++ b)
        concatenated <- convertDERToConcatenated(der, outputLength)
      yield
        val first = concatenated.leftHalf
        val second = concatenated.rightHalf
        outputLength == concatenated.length && a === first && b === second
    IO.unit.asserting(_ => assert(either.getOrElse(false)))
  }

  "ECDSA" should "succeed with too short previously" in {
    // a ECDSA 521 sig value produced before jose4j left zero padded the R & S values
    val encoded = "7w6JjwMqcWmTFaZfrOc5kSSj5WOi0vDbMoGqcLWUL5QrTmJ_KOPMkNOjNll4pRITxuyZo_owOswnDM4dYdS7ypoPHOL13XDfd" +
      "ffG7sdwjXA6JthsItlk6l43Xtqt2ytJKqUMC-J7K5Cn1izOeuqzsI18Go9jcEEw5eUdQhR77OjfCA"
    val outputLength = 132
    val either =
      for
        base <- Base64UrlNoPad.fromString(encoded)
        decoded <- base.decode[Id]
        der <- convertConcatenatedToDER(decoded)
        concatenated <- convertDERToConcatenated(der, outputLength)
      yield
        outputLength == concatenated.length && concatenated(0) == 0 && concatenated(66) == 0
    IO.unit.asserting(_ => assert(either.getOrElse(false)))
  }

  "ECDSA" should "succeed with backward compatibility" in {
    List(
      check(
        "{\"kty\":\"EC\",\"x\":\"APlFpj7M-Kj8ArsYMbJS-6rn1XkugUwngk_iTVe_KfLs6pVIb4LYz-gJ2SytwsoNkSbwq6NuNXB3kFsiYXm" +
          "G0pf2\",\"y\":\"AebLEK2Hn_vLyDFCzQYGBrGF7eJPh2b01vZ_rK1UOXT9slDvNFK5y6yUSkG4qrVg5P0xwuw25AReYwtvwYQr8uvV" +
          "\",\"crv\":\"P-521\",\"d\":\"AL-txDgStuoyYEJ3-NyMNeTjlwcoQxbck659Snelqza-Vhd166l3Bfh4A0o42DqetfknQBeE-upP" +
          "EliNEtEvv9dN\"}",
        "eyJhbGciOiJFUzUxMiJ9.ZG9lcyBpdCBtYXR0ZXIgd2hhdCdzIGluIGhlcmU_IEkgZG9uOyd0IGtub3cuLi4.zv6B3bm8xz6EKfQaaW-0sV" +
          "VD7MYoym-cXrq2SaDGI9_EZkP244jQk1xtyX6uK8JlSXXRlYR7WJ2rCM8NOr_ZHB5b7VaJnOnJkzRnh3-ncI46Dhj-cbqsVqZvvylkWDx" +
          "hoodVkhAPT2wnkbfS6mYHjmYzWI1YF2ub5klAunLjn8jFdg"
      ),
      check(
        "{\"kty\":\"EC\",\"x\":\"ACDqsfERDEacSJUa-3M2TxIp05yVHl5yuURP0WhZvi4xfMiRsyqooEWhA9PtHEko1ELvaM0bR0hNavo597H" +
          "tP5_q\",\"y\":\"AW90m8N4e9YUwYG-Yxkf5T2rR5fiECj-A0p1DVUJNJ8BFPr5OGG1z3GO_PMxC-7LCj8gfqr6Wc8a1ViqIt6OE8Nr" +
          "\",\"crv\":\"P-521\",\"d\":\"AGS5ZSjsn_ou9mqkutgJAUKz5Hx7XATfHvNTUv_1CAHN08LVBU_1R2TEtJanWe72w3d22ylwHTPo" +
          "ogAbRQdhTyYC\"}",
        "eyJhbGciOiJFUzUxMiJ9.ZG9lcyBpdCBtYXR0ZXIgd2hhdCdzIGluIGhlcmU_IEkgZG9uOyd0IGtub3cuLi4.k-m9qenb1rrmhpavhQ6Pek" +
          "lKRXn7Tu7J9Asycgj4gUELLTGHE96Di5_euQF0avKkVrorDuDdtzi-q0hnzq38ArKTpbkjRqdMonQdhFTXroP6HCkSrlSWFUTxvtsoaa-" +
          "VorugOxPe1wZSHafmaWotbqDJ2jXA3sSC1H3jVxx1SxXGRg"
      ),
      check(
        "{\"kty\":\"EC\",\"x\":\"AQ8WdkBzMgfuWCWvGIpGkyi-DZgw4a1wmTZVg9YjUzSUj8NKLDcYnUgsr4op7z8dW8WUib6dC4EGXISaye1" +
          "Svp6S\",\"y\":\"AMr47PiklLy_Py-QgB1jOsoVlbujFwDuM6vdTorColeNVWw2FQi-oUN-Pt8ga9mD1LDgAC96lTSybpgTu9G1P_ir" +
          "\",\"crv\":\"P-521\",\"d\":\"AaDOIsjeA20NpIDcQN6yBZ-I1XEOQSsolqsZBSWllmNjVfefggm-Erjz4UdWrgKVdZNlD5px3i5L" +
          "30dhWZc-45kC\"}",
        "eyJhbGciOiJFUzUxMiJ9.ZG9lcyBpdCBtYXR0ZXIgd2hhdCdzIGluIGhlcmU_IEkgZG9uOyd0IGtub3cuLi4.waSI2xpnm4zQeAyyRLDmoq" +
          "5nf_tj9SoSxLvXWcYhpNX56UVM3PyyCkX5aIzGH25kJ-W-10QzF-tR8PoIHxlNEMgfJFGHW4Bjexe-juNyvnETJbDyipP_i4t0wuUIVJ1" +
          "J43ihHvLhXiWgfivNjwfVikMC3mTWdyzUxwrjG4M0XaUC-w"
      )
    ).sequence.value.asserting(value => assert(value.isRight))
  }

  private def check(jwkJson: String, cs: String): EitherT[IO, Error, Unit] =
    for
      jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
      key <- EitherT(jwk.toKey[IO]())
      jws <- JsonWebSignature.parse(cs).asError.eLiftET[IO]
      _ <- EitherT(jws.check[IO](Some(key)))
    yield
      ()

end ECDSAFlatSpec
