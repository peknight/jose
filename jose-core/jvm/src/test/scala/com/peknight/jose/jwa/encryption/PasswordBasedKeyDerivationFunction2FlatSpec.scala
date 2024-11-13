package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwx.toBytes
import com.peknight.security.key.secret.PBKDF2
import com.peknight.security.mac.*
import com.peknight.security.spec.PBEKeySpec
import com.peknight.validation.std.either.isTrue
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class PasswordBasedKeyDerivationFunction2FlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  "PasswordBasedKeyDerivationFunction2" should "succeed with iteration count" in {
    val tests = for c <- List(1, 2, 3, 4, 100) yield deriveAndCompare("somepass", "salty!", c, 20)
    tests.sequence.value.map(_.isRight).asserting(assert)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with iteration length" in {
    val tests = for dkLen <- List(4, 16, 20, 21, 32, 64, 65) yield deriveAndCompare("password", "sssss", 100, dkLen)
    tests.sequence.value.map(_.isRight).asserting(assert)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with some randoms" in {
    List(
      deriveAndCompare("pwd", "xxx", 1, 40),
      deriveAndCompare("alongerpasswordwithmorelettersinit", "abcdefghijklmnopqrstuv1234000001ccd", 10, 16),
      deriveAndCompare("password", "yyyy", 10, 1),
      deriveAndCompare("ppppppppp", "sssss", 1000, 21),
      deriveAndCompare("meh", "andmeh", 100, 20),
    ).sequence.value.map(_.isRight).asserting(assert)
  }

  def deriveAndCompare(password: String, salt: String, iterationCount: Int, dkLen: Int): EitherT[IO, Error, Unit] =
    for
      passwordBytes <- ByteVector.encodeAscii(password).asError.eLiftET[IO]
      saltBytes <- ByteVector.encodeAscii(salt).asError.eLiftET[IO]
      derived <- PasswordBasedKeyDerivationFunction2.derive[IO](HmacSHA1, passwordBytes, saltBytes, iterationCount,
        dkLen, None)
      secretKey <- EitherT(PBKDF2.withPRF(HmacSHA1).generateSecret[IO](PBEKeySpec(password, saltBytes, iterationCount,
        dkLen * 8)).asError)
      _ <- isTrue(derived === ByteVector(secretKey.getEncoded), Error("Derived key not match")).eLiftET[IO]
    yield
      ()

  "PasswordBasedKeyDerivationFunction2" should "succeed with pbkdf part from jwk appendix C" in {
    // just the pbkdf2 part from http://tools.ietf.org/html/draft-ietf-jose-json-web-key-22#appendix-C
    val pass = "Thus from my lips, by yours, my sin is purged."
    val salt = ByteVector(80, 66, 69, 83, 50, 45, 72, 83, 50, 53, 54, 43, 65, 49, 50, 56, 75, 87, 0, 217, 96, 147, 112,
      150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215)
    val iterationCount = 4096
    val expectedDerived = ByteVector(110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75)
    val run =
      for
        passwordBytes <- ByteVector.encodeAscii(pass).asError.eLiftET[IO]
        derived <- PasswordBasedKeyDerivationFunction2.derive[IO](HmacSHA256, passwordBytes, salt, iterationCount,
          16, None)
      yield
        derived === expectedDerived
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with test 1" in {
    val iterationCount = 1024
    val salt = "_bdWuYq60PU"
    val dkLen = 16
    val password = "password7"
    val prf = HmacSHA256
    val expectedKey = "uDd04RmfZgf4u-ajXdPhwA"
    testPasswordKeyDerivationFunction2(prf, password, salt, iterationCount, dkLen, expectedKey)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with test 2" in {
    val iterationCount = 500
    val salt = "4qJnWHair2GDKxXd9SYE64MA"
    val dkLen = 64
    val password = "passpass"
    val prf = HmacSHA256
    val expectedKey = "zEZlBzGg2LkthRoJHApI7chEuQuQ57uTDWIhEUw-VR6eq7rQ4ETLYeVy_8nCJUCJPmzCZ2WmNtP-fUfF3YzDHw"
    testPasswordKeyDerivationFunction2(prf, password, salt, iterationCount, dkLen, expectedKey)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with test 3" in {
    val iterationCount = 7
    val salt = "SCZwvZ_lZek"
    val dkLen = 32
    val password = "passthattherepass"
    val prf = HmacSHA384
    val expectedKey = "_uNqQq9PjSmsAmTnnz0fGM4d2noW4JrVCNNiE4yxf4M"
    testPasswordKeyDerivationFunction2(prf, password, salt, iterationCount, dkLen, expectedKey)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with test 4" in {
    val iterationCount = 20
    val salt = "eGOROhJ6jDqos0hYhQh8EYfGJ7g"
    val dkLen = 32
    val password = "blahblah"
    val prf = HmacSHA512
    val expectedKey = "24s7jqUazZ6QHmkU5UyyLw22zeSK87bEmAeugxDDYM4"
    testPasswordKeyDerivationFunction2(prf, password, salt, iterationCount, dkLen, expectedKey)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with test 5" in {
    val iterationCount = 1
    val salt = "WKSJ8q-EvvyP-0RQd6g"
    val dkLen = 16
    val password = "blahblahblahblah"
    val prf = HmacSHA256
    val expectedKey = "6a1-B_PrQu-Pfi9-6w_Y5A"
    testPasswordKeyDerivationFunction2(prf, password, salt, iterationCount, dkLen, expectedKey)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with test 6" in {
    val iterationCount = 3
    val salt = "SldHVNgHJadJ"
    val dkLen = 128
    val password = "dabears"
    val prf = HmacSHA256
    val expectedKey = "nperkSKKFADfulz5xpNkvBrbLK6z075ZUgssE72EWY0vbijZo1rT8pyBhS-hHLcXJi03LXb0E8383sIYjsZInH5OupD4d" +
      "LWXLiE4ZTB1HV8dESTwQug_M7EqVKqIbGW2HV2k5CQUfN2cK9V1U3Jmi0oEJps2fS12jXlMqbNA--Y"
    testPasswordKeyDerivationFunction2(prf, password, salt, iterationCount, dkLen, expectedKey)
  }

  def testPasswordKeyDerivationFunction2(prf: MACAlgorithm, password: String, saltBaseString: String,
                                         iterationCount: Int, dkLen: Int, expectedKey: String): IO[Assertion] =
    val run =
      for
        passwordBytes <- toBytes(password).eLiftET[IO]
        saltBase <- Base64UrlNoPad.fromString(saltBaseString).eLiftET[IO]
        saltBytes <- saltBase.decode[Id].eLiftET[IO]
        derived <- PasswordBasedKeyDerivationFunction2.derive[IO](prf, passwordBytes, saltBytes, iterationCount,
          dkLen, None)
        derivedKey = Base64UrlNoPad.fromByteVector(derived).value
      yield
        derivedKey == expectedKey
    run.value.asserting(value => assert(value.getOrElse(false)))

  "PasswordBasedKeyDerivationFunction2" should "succeed with RFC6070 test 1" in {
    val password = "password"
    val salt = "salt"
    val iterationCount = 1
    val dkLen = 20
    val expectedOutput = ByteVector(12, 96, -56, 15, -106, 31, 14, 113, -13, -87, -75, 36, -81, 96, 18, 6, 47, -32, 55,
      -90)
    testAndCompare(password, salt, iterationCount, dkLen, expectedOutput)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with RFC6070 test 2" in {
    val password = "password"
    val salt = "salt"
    val iterationCount = 2
    val dkLen = 20
    val expectedOutput = ByteVector(-22, 108, 1, 77, -57, 45, 111, -116, -51, 30, -39, 42, -50, 29, 65, -16, -40, -34, 
      -119, 87)
    testAndCompare(password, salt, iterationCount, dkLen, expectedOutput)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with RFC6070 test 3" in {
    val password = "password"
    val salt = "salt"
    val iterationCount = 4096
    val dkLen = 20
    val expectedOutput = ByteVector(75, 0, 121, 1, -73, 101, 72, -102, -66, -83, 73, -39, 38, -9, 33, -48, 101, -92, 41,
      -63)
    testAndCompare(password, salt, iterationCount, dkLen, expectedOutput)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with RFC6070 test 4" in {
    val password = "password"
    val salt = "salt"
    val iterationCount = 16777216
    val dkLen = 20
    val expectedOutput = ByteVector(-18, -2, 61, 97, -51, 77, -92, -28, -23, -108, 91, 61, 107, -94, 21, -116, 38, 52, 
      -23, -124)
    testAndCompare(password, salt, iterationCount, dkLen, expectedOutput)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with RFC6070 test 5" in {
    val password = "passwordPASSWORDpassword"
    val salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
    val iterationCount = 4096
    val dkLen = 25
    val expectedOutput = ByteVector(61, 46, -20, 79, -28, 28, -124, -101, -128, -56, -40, 54, 98, -64, -28, 74, -117,
      41, 26, -106, 76, -14, -16, 112, 56)
    testAndCompare(password, salt, iterationCount, dkLen, expectedOutput)
  }

  "PasswordBasedKeyDerivationFunction2" should "succeed with RFC6070 test 6" in {
    val password = "pass\u0000word"
    val salt = "sa\u0000lt"
    val iterationCount = 4096
    val dkLen = 16
    val expectedOutput = ByteVector(86, -6, 106, -89, 85, 72, 9, -99, -52, 55, -41, -16, 52, 37, -32, -61)
    testAndCompare(password, salt, iterationCount, dkLen, expectedOutput)
  }

  def testAndCompare(password: String, salt: String, iterationCount: Int, dkLen: Int, expectedOutput: ByteVector)
  : IO[Assertion] =
    val run =
      for
        passwordBytes <- toBytes(password).eLiftET[IO]
        saltBytes <- toBytes(salt).eLiftET[IO]
        derived <- PasswordBasedKeyDerivationFunction2.derive[IO](HmacSHA1, passwordBytes, saltBytes, iterationCount,
          dkLen, None)
      yield
        derived === expectedOutput
    run.value.asserting(value => assert(value.getOrElse(false)))
end PasswordBasedKeyDerivationFunction2FlatSpec
