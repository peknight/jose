package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.`try`.asError as tryAsError
import com.peknight.error.syntax.applicativeError.asET
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.{ES256, RS256}
import com.peknight.jose.jwk.*
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jwx.{JoseConfig, JoseHeader}
import com.peknight.security.cipher.RSA
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import scala.util.Try

class PayloadVariationsFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "PayloadVariations" should "succeed with raw bytes as payload" in {
    val bytesIn = ByteVector(-98, 96, -6, 55, -118, -17, -128, 13, 126, 14, 90, -21, -91, -7, -50, -57, 37, 79, 10, 45,
      52, 77, 87, -24, -18, -94, -45, 100, -18, 110, -20, -23, -123, 120, 99, -43, 115, 126, 103, 0, -18, -43, 22, -76,
      -84, 127, -110, 7, 78, -109, 44, 81, 119, -73, -115, -10, 18, 27, -113, -104, 14, -50, -105, -41, -49, 25, 26,
      116, -37, -42, 75, -109, -30, -62, 117, -44, 100, -114, 43, -125, 123, 39, -79, -55, -111, -36, 86, 42, -55, 123,
      -16, -74, 119, 59, -68, -4, -119, -118, -101, -76)
    val run =
      for
        privateKey <- RSA.privateKey[IO](n, d).asET
        jws <- EitherT(JsonWebSignature.signBytes[IO](JoseHeader(Some(RS256)), bytesIn, Some(privateKey)))
        compact <- jws.compact.eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).eLiftET[IO]
        publicKey <- RSA.publicKey[IO](n, e).asET
        bytesOut <- EitherT(parsedJws.verifiedPayloadBytes[IO](Some(publicKey)))
      yield
        bytesIn === bytesOut
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PayloadVariations" should "failed with get payload bytes throws on bad signature" in {
    val bytesIn = ByteVector(12, 6, -16, 44, 0, -17, -128, 113, 126, 14, 43, -121, 123, 35, -40, -7, 37, 79, 10, 45, 77,
      77)
    val wrongKeyJson = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"xLyNk8AVckm8PPwxHfenLe1MvDHJL4UsOqGgbyAsEBqrATEg0aap" +
      "HuwJPFoiRCHQW0cgA8B9V8_MElHtMmU89VLRIeln7WCouCasO1rl2DHvBZAGhDLX5yDNTPs8-jrrZKqE_KgJQZV0KphDcwIVwgljtswPLiP2F" +
      "gqjbnUivVM7wHbMR6kdl_FP-VwmWJFUYCtHVOJ9DalhATFndThCZ-LAgjt6tAuWiW6kEUtXuX3RfMNHh1AOufLeHp7ywmh6DhSfOjcBNVHz9W" +
      "i6vlAPhYpk2G9xXtE9-78z76lR2T0YtULN7xDRwHSq1ub_T3Y4whxp4jYbVWRuOkqifz3TuQ\"}"
    val run =
      for
        privateKey <- RSA.privateKey[IO](n, d).asET
        jws <- EitherT(JsonWebSignature.signBytes[IO](JoseHeader(Some(RS256)), bytesIn, Some(privateKey)))
        compact <- jws.compact.eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).eLiftET[IO]
        wrongKey <- decode[Id, AsymmetricJsonWebKey](wrongKeyJson).eLiftET[IO]
        publicKey <- EitherT(wrongKey.toKey[IO]())
        bytesOut <- parsedJws.decodePayload().eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(publicKey)).map(_.swap.asError))
      yield
        bytesIn === bytesOut
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PayloadVariations" should "succeed with payload char encoding ASCII" in {
    val run =
      for
        privateKey <- ES256.curve.privateKey[IO](d256).asET
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(ES256)), "pronounced as'-key", Some(privateKey),
          JoseConfig(charset = StandardCharsets.US_ASCII)))
        compact <- jws.compact.eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).eLiftET[IO]
        publicKey <- ES256.curve.publicKey[IO](x256, y256).asET
        payload <- EitherT(parsedJws.verifiedPayloadString[IO](Some(publicKey),
          JoseConfig(charset = StandardCharsets.US_ASCII)))
      yield
        payload == "pronounced as'-key"
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "PayloadVariations" should "succeed with payload char encoding ISO8859_15" in {
    val run =
      for
        charset <- Try(Charset.forName("ISO8859_15")).tryAsError.eLiftET[IO]
        privateKey <- ES256.curve.privateKey[IO](d256).asET
        jws <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(ES256)), "€Ÿ", Some(privateKey),
          JoseConfig(charset = charset)))
        compact <- jws.compact.eLiftET[IO]
        parsedJws <- JsonWebSignature.parse(compact).eLiftET[IO]
        publicKey <- ES256.curve.publicKey[IO](x256, y256).asET
        payload <- parsedJws.decodePayloadString(charset).eLiftET[IO]
        _ <- parsedJws.decodePayloadString(StandardCharsets.US_ASCII).swap.asError.eLiftET[IO]
        _ <- EitherT(parsedJws.check[IO](Some(publicKey)))
      yield
        payload == "€Ÿ"
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end PayloadVariationsFlatSpec
