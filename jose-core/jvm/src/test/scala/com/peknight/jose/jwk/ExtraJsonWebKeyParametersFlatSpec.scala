package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwk.JsonWebKey.{OctetSequenceJsonWebKey, RSAJsonWebKey}
import com.peknight.jose.jwx.encodeToJson
import com.peknight.security.cipher.RSA
import io.circe.{Json, JsonObject}
import org.scalatest.flatspec.AsyncFlatSpec

import java.security.{Key, PublicKey}

class ExtraJsonWebKeyParametersFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKey" should "succeed with parsing custom params" in {
    val json = "{\"kty\":\"EC\",\"x\":\"14PCFt8uuLb6mbfn1XTOHzcSfZk0nU_AGe2hq91Gvl4\",\"y\":\"U0rLlwB8be5YM2ajGyactl" +
      "plFol7FKJrN83mNAOpuss\",\"crv\":\"P-256\",\"meh\":\"just some value\",\"number\":860}"
    val flag = decode[Id, JsonWebKey](json).map{ jwk =>
      val json = encodeToJson(jwk)
      jwk.ext("meh").flatMap(_.asString).contains("just some value") &&
        jwk.ext("number").flatMap(_.asNumber).flatMap(_.toInt).contains(860) &&
        json.contains("\"meh\"") &&
        json.contains("\"just some value\"") &&
        json.contains("\"number\"") &&
        json.contains("860")
    }.isRight
    IO.unit.asserting(_ => assert(flag))
  }

  "JsonWebKey" should "succeed with key with custom params" in {
    val name = "artisanal"
    val value = "parameter"
    given CanEqual[PublicKey, PublicKey] = CanEqual.derived
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        jwk = JsonWebKey.fromRSAKey(publicKey, ext = JsonObject(name -> Json.fromString(value)))
        json = encodeToJson(jwk)
        decodedJwk <- decode[Id, RSAJsonWebKey](json).eLiftET[IO]
        decodedPublicKey <- EitherT(decodedJwk.toPublicKey[IO]())
      yield
        jwk.ext(name).flatMap(_.asString).contains(value) &&
          json.contains(s"\"$name\"") && json.contains(s"\"$value\"") &&
          publicKey == decodedPublicKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKey" should "succeed with round trip oct key" in {
    val name = "artisanal"
    val value = "parameter"
    val json = s"{\"kty\":\"oct\",\"k\":\"jr-TRYPvKkOxw_cBB5y4plEX5cEUT1AawUU7G3id7u4\",\"$name\":\"$value\"}"
    given CanEqual[Key, Key] = CanEqual.derived
    val run =
      for
        jwk<- decode[Id, OctetSequenceJsonWebKey](json).eLiftET[IO]
        key <- jwk.toKey.eLiftET[IO]
        encodedJson = encodeToJson(jwk)
        decodedJwk <- decode[Id, OctetSequenceJsonWebKey](encodedJson).eLiftET[IO]
        decodedKey <- decodedJwk.toKey.eLiftET[IO]
      yield
        jwk.ext(name).flatMap(_.asString).contains(value) &&
          encodedJson.contains(s"\"k\"") && encodedJson.contains(s"\"$name\"") && encodedJson.contains(s"\"$value\"") &&
          key == decodedKey
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end ExtraJsonWebKeyParametersFlatSpec
