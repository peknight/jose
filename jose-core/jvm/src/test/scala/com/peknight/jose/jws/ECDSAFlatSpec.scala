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
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.ecc.{`P-256K`, `P-256`}
import com.peknight.jose.jwa.signature.{ES256, ES256K}
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jwk.{JsonWebKey, x256, y256}
import com.peknight.jose.jws.JsonWebSignatureTestOps.testBasicRoundTrip
import com.peknight.scodec.bits.ext.syntax.byteVector.{leftHalf, rightHalf}
import com.peknight.security.Security
import com.peknight.security.bouncycastle.jce.provider.BouncyCastleProvider
import com.peknight.security.signature.ECDSA.{convertConcatenatedToDER, convertDERToConcatenated}
import com.peknight.validation.std.either.isTrue
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import java.security.PublicKey

class ECDSAFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  "ECDSA Algorithm" should "succeed with encoding decoding" in {
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

  "ECDSA Algorithm" should "succeed with simple concatenation with length" in {
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

  "ECDSA Algorithm" should "succeed with simple concatenation with diff lengths" in {
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

  "ECDSA Algorithm" should "succeed with simple concatenation with very diff lengths" in {
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

  "ECDSA Algorithm" should "succeed with too short previously" in {
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

  "ECDSA Algorithm" should "succeed with backward compatibility" in {
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

  "ECDSA Edges" should "failed with zeros" in {
    val jws = "eyJhbGciOiJFUzI1NiJ9.RXZlcnlvbmUgcHJldGVuZHM.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    val run =
      for
        publicKey <- EitherT(`P-256`.publicKey[IO](x256, y256).asError)
        _ <- expectInvalidSignature(jws, publicKey)
      yield ()
    run.value.asserting(value => assert(value.isRight))
  }

  "ECDSA Edges" should "failed with same as order" in {
    // https://twitter.com/phLaul/status/1517209015649914881
    val jws = "eyJhbGciOiJFUzI1NiJ9.RXZlcnlvbmUgcHJldGVuZHM._____wAAAAD__________7zm-q2nF56E87nKwvxjJVH_____AAAAAP__" +
      "________vOb6racXnoTzucrC_GMlUQ"
    val run =
      for
        publicKey <- EitherT(`P-256`.publicKey[IO](x256, y256).asError)
        _ <- expectInvalidSignature(jws, publicKey)
      yield ()
    run.value.asserting(value => assert(value.isRight))
  }

  "ECDSA Edges" should "failed with some of the wycheproof stuff P-256" in {
    val jwkJson =
      s"""
         |{
         |  "crv": "P-256",
         |  "kid": "none",
         |  "kty": "EC",
         |  "x": "KSexBRK64-3c_kZ4KBKLrSkDJpkZ9whgacjE32xzKDg",
         |  "y": "x3h5ZOqsAOWSH7FJimD0YGdms9loUAFVjRqXTnNBUT4"
         |}
      """.stripMargin
    val hexSigs = List(
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000",
      "012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf536900b329f479a2bbd0a5c384ee1493b1f5186a87139ca" +
       "c5df4087c134b49156847db",
      "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df" +
       "4087c134b49156847db",
      "012ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1800b329f479a2bbd0a5c384ee1493b1f5186a87139ca" +
       "c5df4087c134b49156847db",
      "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df" +
       "4087c134b49156847db",
      "002ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1801b329f478a2bbd0a6c384ee1493b1f518276e0e4a5" +
       "375928d6fcd160c11cb6d2c",
      "002ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1801b329f479a2bbd0a5c384ee1493b1f5186a87139ca" +
       "c5df4087c134b49156847db",
      "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b865d442f5a3c7b11eb6c4e0ae79578ec6353a20" +
       "bf783ecb4b6ea97b825",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000000fffff" +
       "fffffffffffffffffff",
      "0000000000000000000000000000000000000000000000000000000000000000ffffffff0000000100000000000000000000000100000" +
       "0000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000" +
       "0000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000" +
       "0000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000000fffff" +
       "fffffffffffffffffff",
      "0000000000000000000000000000000000000000000000000000000000000001ffffffff0000000100000000000000000000000100000" +
       "0000000000000000000",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551000000000000000000000000000000000000000000000" +
       "0000000000000000000",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551000000000000000000000000000000000000000000000" +
       "0000000000000000001",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000001000000000000000000000000fffff" +
       "fffffffffffffffffff",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff0000000100000000000000000000000100000" +
       "0000000000000000000",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550000000000000000000000000000000000000000000000" +
       "0000000000000000000",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550000000000000000000000000000000000000000000000" +
        "0000000000000000001",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000001000000000000000000000000fffff" +
       "fffffffffffffffffff",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff0000000100000000000000000000000100000" +
       "0000000000000000000",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552000000000000000000000000000000000000000000000" +
       "0000000000000000000",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552000000000000000000000000000000000000000000000" +
       "0000000000000000001",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000001000000000000000000000000fffff" +
       "fffffffffffffffffff",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff0000000100000000000000000000000100000" +
       "0000000000000000000",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff000000000000000000000000000000000000000000000" +
       "0000000000000000000",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff000000000000000000000000000000000000000000000" +
        "0000000000000000001",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000000fffff" +
       "fffffffffffffffffff",
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff0000000100000000000000000000000100000" +
       "0000000000000000000",
      "ffffffff00000001000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000",
      "ffffffff00000001000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000001",
      "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632551",
      "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632550",
      "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179" +
       "e84f3b9cac2fc632552",
      "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000001000000000000000000000000fffff" +
        "fffffffffffffffffff",
      "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff0000000100000000000000000000000100000" +
        "0000000000000000000"
    )
    testSomeOfTheWycheproofStuff(jwkJson, hexSigs, "eyJhbGciOiJFUzI1NiJ9.RXZlcnlvbmUgcHJldGVuZHM.")
  }

  "ECDSA Edges" should "failed with some of the wycheproof stuff P-384" in {
    val jwkJson =
      s"""
         |{
         |  "crv": "P-384",
         |  "kid": "none",
         |  "kty": "EC",
         |  "x": "LaV92hCJJ2pUP5_9rAv_DZdsrXHrcoDn2b_Z_uS9svIPR_-IgnQ4l3LZjMV1ITiq",
         |  "y": "S20FTWnc8-JexJ34cHFeNIg7GDYZfXb4rZYuePZXG7x0B7DWCR-eTYjwFCdEBhdP"
         |}
      """.stripMargin
    val hexSigs = List(
      "0112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19a25617aad7485e6312a8589714f647acf7a94cffbe8a724a00e7bf25603" +
        "e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82",
      "ed4cf541094ab8901949ed51aa83fbda99e1d94bb4e401e5ec7083591125fd5b9d8bc2cd7c6b0748e22ee5d5daffe09ce7bf25603e2d0" +
       "7076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82",
      "0112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d700e7bf25603" +
       "e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82",
      "ed4cf541094ab8901949ed51aa83fbda99e1d94bb4e401e6250d35d71ceecf7c4571b51b33ba5fcdf542cc6b0e3ab729e7bf25603e2d0" +
       "7076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82",
      "0012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d701e7bf25603" +
       "e2d07076ff30b7a2abec473da8b11c572b35fc5f8fc6adfda650a86aa74b95adbd6874b3cd8dde6cc0798f5",
      "0012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d701e7bf25603" +
       "e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82",
      "12b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d71840da9fc1d2f" +
       "8f8900cf485d5413b8c2574ee3a8d4ca039ce66e2a219d22358ada554576cda202fb0133b8400bd907e",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc529730000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc529730000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc529720000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc529720000000000000" +
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc529740000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc529740000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974fffffffffffff" +
       "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974fffffffffffff" +
       "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff0000000000000" +
       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff0000000000000" +
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffffffffffffffff" +
        "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffffffffffffffff" +
      "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffffffffffffffff" +
      "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffffffffffffffff" +
      "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffffffffffffffff" +
      "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000001000000000000000000000" +
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000001000000000000000000000" +
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000001",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000fffffffffffff" +
        "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000fffffffffffff" +
        "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000fffffffffffff" +
        "fffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000fffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000fffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000"
    )
    testSomeOfTheWycheproofStuff(jwkJson, hexSigs, "eyJhbGciOiJFUzI1NiJ9.RXZlcnlvbmUgcHJldGVuZHM.")
  }

  "ECDSA Edges" should "failed with some of the wycheproof stuff P-521" in {
    val jwkJson =
      s"""
         |{
         |  "crv": "P-521",
         |  "kid": "none",
         |  "kty": "EC",
         |  "x": "AFxkV-wIjVMvSCCTllrlPM0H5VbtWeKvlFzYx6lcHGRPilaoqKPNdzkt3YYeipJNrJnGkGkJO9UqUvpsVgBKB0UI",
         |  "y": "AHh41tQuS03R6cBpbLPhn2MDPD205g1HMlmz6-B5qvCphu5hd_ghenjGi4E_fhSaTlb9lWLAf-09iVlC19EBy4P2"
         |}
      """.stripMargin
    val hexSigs = List(
      "024e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbe97b3367122fa4a20584c271233f3ec3b7f7b31b0fa" +
        "a4d340b92a6b0d5cd17ea4e0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174db" +
        "a2fe747122709a69ce69d5285e174a01a93022fea8318ac1",
      "01b1bddc11bc17347621c4ecc6003d861a7d07d3854f08e4421bc241c8b538a0040b27d9a7f54eba8ad17ad5916eaed487e87fb878616" +
       "8eb5b51e438bd675558ddc40028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba" +
        "2fe747122709a69ce69d5285e174a01a93022fea8318ac1",
      "024e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd51572" +
       "0b0ec5cd736f9b73bdf86450028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba" +
        "2fe747122709a69ce69d5285e174a01a93022fea8318ac1",
      "01b1bddc11bc17347621c4ecc6003d861a7d07d3854f08e4421bc241c8b538a00410d65320718f8af465fb099025b7cae2184402aea8d" +
       "f4f13a328c90648c42079bb0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba" +
        "2fe747122709a69ce69d5285e174a01a93022fea8318ac1",
      "004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd51572" +
       "0b0ec5cd736f9b73bdf86450228b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba09a7b6ac4ecd0410b472" +
        "2ca75ba197a403a0a1f9ee0e7b391b0649fda1d3969eeca",
      "004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd51572" +
       "0b0ec5cd736f9b73bdf86450228b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba" +
        "2fe747122709a69ce69d5285e174a01a93022fea8318ac1",
      "004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd51572" +
       "0b0ec5cd736f9b73bdf864501d74a2f6d95be8d4cb64f02d16d6b785a1246b4ebd206dc596818bb953253245f5fd61bc296eeee8b245" +
        "d018b8edd8f659631962ad7a1e8b5fe56cfdd0157ce753f",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7" +
        "fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7" +
        "fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7" +
        "fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffffffffffffffffffffffffffff",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000101fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7" +
        "fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000101fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7" +
        "fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000101fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7" +
        "fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
       "0000000000000000000000101fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffffffffffffffffffffffffffff",
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000001020000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e91386409000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e91386409000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000001",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640901fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640901fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640901fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640901ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e91386409020000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e91386408000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e91386408000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000001",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640801fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640801fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640801fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640801ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e91386408020000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000001",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b88" +
        "99c47aebb6fb71e9138640a020000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000001",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "fffffffffffffffffffffff020000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000001",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b" +
        "7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000"
    )
    testSomeOfTheWycheproofStuff(jwkJson, hexSigs, "eyJhbGciOiJFUzUxMiJ9.ZmZz.")
  }

  private def testSomeOfTheWycheproofStuff(jwkJson: String, hexSigs: List[String], data: String): IO[Assertion] =
    val run =
      for
        jwk <- decode[Id, AsymmetricJsonWebKey](jwkJson).eLiftET[IO]
        publicKey <- EitherT(jwk.toPublicKey[IO]())
        _ <- hexSigs.traverse { hexSig =>
          for
            sig <- ByteVector.fromHexDescriptive(hexSig).asError.eLiftET[IO]
            encodeSig = sig.toBase64UrlNoPad
            _ <- expectInvalidSignature(s"$data$encodeSig", publicKey)
          yield
            ()
        }
      yield ()
    run.value.asserting(value => assert(value.isRight))

  private def expectInvalidSignature(jws: String, key: PublicKey): EitherT[IO, Error, Unit] =
    for
      jws <- JsonWebSignature.parse(jws).asError.eLiftET[IO]
      _ <- EitherT(jws.check[IO](Some(key)).map(_.swap.asError))
    yield
      ()

  "ECDSA" should "succeed with P-256 round trip gen keys" in {
    val run =
      for
        keyPair1 <- EitherT(`P-256`.generateKeyPair[IO]().asError)
        keyPair2 <- EitherT(`P-256`.generateKeyPair[IO]().asError)
        _ <- testBasicRoundTrip("PAYLOAD!!!", ES256, keyPair1.getPrivate, keyPair1.getPublic, keyPair2.getPrivate,
          keyPair2.getPublic)
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "ECDSA" should "succeed with ES256K round trip gen keys" in {
    val run =
      for
        provider <- EitherT(BouncyCastleProvider[IO].asError)
        _ <- EitherT(Security.addProvider[IO](provider).asError)
        keyPair1 <- EitherT(ES256K.curve.generateKeyPair[IO](provider = Some(provider)).asError)
        keyPair1Jwk <- JsonWebKey.fromKeyPair(keyPair1).eLiftET[IO]
        keyPair1Jwk <- JsonWebKey.fromKeyPair(keyPair1).eLiftET[IO]
        keyPair1 <- EitherT(keyPair1Jwk.toKeyPair[IO](provider = Some(provider)))
        keyPair2 <- EitherT(`P-256K`.generateKeyPair[IO](provider = Some(provider)).asError)
        _ <- testBasicRoundTrip("k", ES256K, keyPair1.getPrivate, keyPair1.getPublic, keyPair2.getPrivate,
          keyPair2.getPublic, Some(provider))
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }

  "ECDSA" should "succeed with external ES256K" in {
    val jwsCs = "eyJraWQiOiJtZWgiLCJhbGciOiJFUzI1NksifQ.eyJzdWIiOiJtZWgifQ.-5KBGAoCZYkE-1cpU8gQZ1SfLCAxd5P0TtDAEuCAh" +
      "Pl57eTMTFqNLXiM09J4lgq0IA35OxNgxIxn3WNFUAXEZg"
    val jwkJson = "{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"secp256k1\",\"kid\":\"meh\",\"x\":\"cWwaOcRUqZE6UMUtOPL" +
      "cNIIouiM7GrdO_gWV47e837I\",\"y\":\"N2vLlH7f_2Y54zKfbUSSQyQxb5oozybb2SsM-eRYpMU\"}"
    val run =
      for
        provider <- EitherT(BouncyCastleProvider[IO].asError)
        _ <- EitherT(Security.addProvider[IO](provider).asError)
        jwk <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        jws <- JsonWebSignature.parse(jwsCs).asError.eLiftET[IO]
        key <- EitherT(jwk.toKey[IO](provider = Some(provider)))
        _ <- EitherT(jws.check[IO](Some(key), provider = Some(provider)))
        payload <- jws.decodePayloadUtf8.eLiftET[IO]
        _ <- isTrue(payload == """{"sub":"meh"}""", Error("payload must equal")).eLiftET[IO]
      yield
        ()
    run.value.asserting(value => assert(value.isRight))
  }
end ECDSAFlatSpec
