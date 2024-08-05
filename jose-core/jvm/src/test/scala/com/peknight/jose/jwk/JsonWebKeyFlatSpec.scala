package com.peknight.jose.jwk

import cats.Id
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.syntax.traverse.*
import com.chatwork.scala.jwk.{Curve, ECJWK}
import com.peknight.codec.circe.parser.ParserOps.decode
import com.peknight.jose.jwa.ecc.`P-384`
import com.peknight.security.bouncycastle.jce.ECNamedCurveTable
import com.peknight.security.bouncycastle.jce.provider.BouncyCastleProvider
import com.peknight.security.bouncycastle.signature.ECDSA
import com.peknight.security.syntax.keyPairGenerator.{generateKeyPairF, initializeF}
import com.peknight.security.{KeyPairGenerator, SecureRandom, Security}
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebKeyFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  given CanEqual[JsonWebKey, JsonWebKey] = CanEqual.derived
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
        joseJwkEither = JsonWebKey.fromKeyPair(keyPair.getPublic, Some(keyPair.getPrivate))
        jose4jJwkEither = decode[Id, JsonWebKey](org.jose4j.jwk.JsonWebKey.Factory.newJwk(keyPair.getPublic).toJson)
        scalaJwkEither = ECJWK.fromKeyPair(Curve.P_384, keyPair.getPublic.asInstanceOf, keyPair.getPrivate.asInstanceOf)
      yield
        (joseJwkEither, jose4jJwkEither, scalaJwkEither) match
          case (Right(joseEcJwk: JsonWebKey.EllipticCurveJsonWebKey), Right(jose4jEcJwk: JsonWebKey.EllipticCurveJsonWebKey), Right(scalaEcJwk)) =>
            joseEcJwk.copy(eccPrivateKey = None) == jose4jEcJwk && joseEcJwk.eccPrivateKey.map(_.value).contains(scalaEcJwk.y.asString)
          case _ => false
    run.asserting(assert)
  }
end JsonWebKeyFlatSpec
