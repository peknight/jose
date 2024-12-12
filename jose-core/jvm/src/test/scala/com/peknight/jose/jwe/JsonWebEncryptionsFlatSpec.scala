package com.peknight.jose.jwe

import cats.Id
import cats.data.{EitherT, NonEmptyList}
import cats.effect.IO
import com.peknight.codec.circe.parser.decode
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.ecc.`P-256`
import com.peknight.jose.jwa.encryption.{A128GCM, `ECDH-ES+A128KW`, `RSA-OAEP`}
import com.peknight.jose.jwk.*
import com.peknight.jose.jwx.{JoseHeader, encodeToJson}
import com.peknight.security.cipher.RSA
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebEncryptionsFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebEncryptions" should "succeed" in {
    val run =
      for
        rsaKeyPair <- EitherT(RSA.keySizeGenerateKeyPair[IO](2048).asError)
        rsaPublicKey = rsaKeyPair.getPublic
        rsaPrivateKey = rsaKeyPair.getPrivate
        ec256KeyPair <- EitherT(`P-256`.generateKeyPair[IO]().asError)
        ec256PublicKey = ec256KeyPair.getPublic
        ec256PrivateKey = ec256KeyPair.getPrivate
        rsaJwk <- JsonWebKey.fromKeyPair(rsaKeyPair).eLiftET[IO]
        ec256Jwk <- JsonWebKey.fromKeyPair(ec256KeyPair).eLiftET[IO]
        jwks = JsonWebKeySet(rsaJwk, ec256Jwk)
        jwes <- EitherT(JsonWebEncryptions.parEncryptString[IO](
          NonEmptyList(
            EncryptionPrimitive(rsaPublicKey, Some(JoseHeader(Some(`RSA-OAEP`)))), List(
              EncryptionPrimitive(ec256PublicKey, Some(JoseHeader(Some(`ECDH-ES+A128KW`))))
            )),
          JoseHeader(encryptionAlgorithm = Some(A128GCM)),
          "Hello, world!"
        ))
        jwesJson = encodeToJson(jwes)
        parsedJwes <- decode[Id, JsonWebEncryptions](jwesJson).eLiftET[IO]
        payloads <- parsedJwes.toList.traverse { jwe =>
          EitherT(jwe.getPayloadString[IO]()(jwks.verificationPrimitives)(jwks.decryptionPrimitives))
        }
      yield
        payloads.forall(_ == "Hello, world!")
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebEncryptionsFlatSpec
