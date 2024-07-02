package com.peknight.jose.jwk

import cats.Show
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.chatwork.scala.jwk.{Curve, ECJWK}
import com.peknight.jose.jwa.ecc.`P-384`
import com.peknight.security.bouncycastle.jce.ECNamedCurveTable
import com.peknight.security.bouncycastle.jce.provider.BouncyCastleProvider
import com.peknight.security.bouncycastle.signature.ECDSA
import com.peknight.security.syntax.keyPairGenerator.{generateKeyPairF, initializeF}
import com.peknight.security.{KeyPairGenerator, SecureRandom, Security}
import io.circe.syntax.*
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKey EC" should "succeed" in {
    val run =
      for
        provider <- BouncyCastleProvider[IO]
        _ <- Security.addProvider[IO](provider)
        keyPairGenerator <- KeyPairGenerator.getInstance[IO](ECDSA, BouncyCastleProvider)
        ecSpec <- ECNamedCurveTable.getParameterSpec[IO](`P-384`.std)
        secureRandom <- SecureRandom[IO]
        _ <- keyPairGenerator.initializeF[IO](ecSpec, secureRandom)
        keyPair <- keyPairGenerator.generateKeyPairF[IO]
        _ <- IO.println(org.jose4j.jwk.JsonWebKey.Factory.newJwk(keyPair.getPublic).toJson)
        _ <- IO.println(ECJWK.fromKeyPair(Curve.P_384, keyPair.getPublic.asInstanceOf, keyPair.getPrivate.asInstanceOf)
          .map(_.asJson.deepDropNullValues.noSpaces).fold(_ => "", identity))
        _ <- IO.println(JsonWebKey
          .fromKeyPair(keyPair.getPublic, Some(keyPair.getPrivate))
          .map(_.asJson.deepDropNullValues.noSpaces)
          .fold(_ => "", identity)
        )
      yield true
    run.asserting(assert)
  }
end JsonWebKeyFlatSpec
