package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwk.JsonWebKey.OctetSequenceJsonWebKey
import com.peknight.jose.jwx.encodeToJson
import com.peknight.security.cipher.AES
import com.peknight.security.mac.Hmac
import com.peknight.validation.std.either.typed
import org.scalatest.flatspec.AsyncFlatSpec
import scodec.bits.ByteVector

class OctetSequenceJsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "OctetSequenceJsonWebKey" should "succeed with example from Jws" in {
    val base64UrlKey = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    val jwkJson = s"""{"kty":"oct", "k":"$base64UrlKey"}"""
    val keyBytes = ByteVector(3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230,
      240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195,
      119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163)
    val run =
      for
        parsedKey <- decode[Id, JsonWebKey](jwkJson).eLiftET[IO]
        json = encodeToJson(parsedKey)
        key <- EitherT(parsedKey.toKey[IO]())
        jwk <- JsonWebKey.fromKey(Hmac.secretKeySpec(keyBytes)).eLiftET[IO]
        json2 = encodeToJson(jwk)
      yield
        json.contains(base64UrlKey) && json.contains("\"k\"") && keyBytes === ByteVector(key.getEncoded) &&
          jwk.keyType == KeyType.OctetSequence && json2.contains(base64UrlKey) && json.contains("\"k\"")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "OctetSequenceJsonWebKey" should "succeed with leading and trailing zeros" in {
    val rawInputBytes = ByteVector(0, 0, 111, 16, 51, 98, -4, 0, -72, 9, -111, 60, 41, -66, 94, 0)
    val run =
      for
        jwk <- JsonWebKey.fromKey(AES.secretKeySpec(rawInputBytes)).eLiftET[IO]
        json = encodeToJson(jwk)
        jwkFromJson <- decode[Id, JsonWebKey](json).eLiftET[IO]
        key <- EitherT(jwkFromJson.toKey[IO]())
        encoded = ByteVector(key.getEncoded)
      yield
        rawInputBytes.length == encoded.length && rawInputBytes === encoded
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "OctetSequenceJsonWebKey" should "succeed with generator" in {
    List(128, 192, 256, 192, 384, 512).map { size =>
      for
        key <- EitherT(AES.keySizeGenerateKey[IO](size).asError)
        jwk <- JsonWebKey.fromKey(key).eLiftET[IO]
        jwk <- typed[OctetSequenceJsonWebKey](jwk).eLiftET[IO]
        key <- jwk.toKey.eLiftET[IO]
        keyValue <- jwk.keyValue.decode[Id].eLiftET[IO]
      yield
        size / 8 == keyValue.length
    }.sequence.map(_.forall(identity)).value.asserting(value => assert(value.getOrElse(false)))
  }
end OctetSequenceJsonWebKeyFlatSpec
