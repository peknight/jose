package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.JWSAlgorithm
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue

import java.security.{Key, Provider as JProvider}

object JsonWebSignatureTestOps:
  def testBasicRoundTrip(payload: String, jwsAlgo: JWSAlgorithm,
                         signingKey1: Key, verificationKey1: Key,
                         signingKey2: Key, verificationKey2: Key,
                         provider: Option[Provider | JProvider] = None): EitherT[IO, Error, Unit] =
    for
      jwsWithKey1 <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(jwsAlgo)), payload, Some(signingKey1),
        provider = provider))
      jwsWithKey2 <- EitherT(JsonWebSignature.signString[IO](JoseHeader(Some(jwsAlgo)), payload, Some(signingKey2),
        provider = provider))
      serializationWithKey1 <- jwsWithKey1.compact.eLiftET[IO]
      serializationWithKey2 <- jwsWithKey2.compact.eLiftET[IO]
      parsedJwsWithKey1 <- JsonWebSignature.parse(serializationWithKey1).eLiftET[IO]
      parsedJwsWithKey2 <- JsonWebSignature.parse(serializationWithKey2).eLiftET[IO]
      jwsWithKey1Payload <- jwsWithKey1.decodePayloadString().eLiftET[IO]
      jwsWithKey2Payload <- jwsWithKey2.decodePayloadString().eLiftET[IO]
      parsedJwsWithKey1Payload <- parsedJwsWithKey1.decodePayloadString().eLiftET[IO]
      parsedJwsWithKey2Payload <- parsedJwsWithKey2.decodePayloadString().eLiftET[IO]
      _ <- isTrue(serializationWithKey1 != serializationWithKey2, Error("compact cannot equal")).eLiftET[IO]
      _ <- EitherT(parsedJwsWithKey1.check[IO](Some(verificationKey1), provider = provider))
      _ <- EitherT(parsedJwsWithKey2.check[IO](Some(verificationKey2), provider = provider))
      _ <- EitherT(parsedJwsWithKey1.check[IO](Some(verificationKey2), provider = provider).map(_.swap.asError))
      _ <- EitherT(parsedJwsWithKey2.check[IO](Some(verificationKey1), provider = provider).map(_.swap.asError))
      _ <- isTrue(jwsWithKey1Payload == payload, Error("payload1 must equal")).eLiftET[IO]
      _ <- isTrue(jwsWithKey2Payload == payload, Error("payload2 must equal")).eLiftET[IO]
      _ <- isTrue(parsedJwsWithKey1Payload == payload, Error("parsedPayload1 must equal")).eLiftET[IO]
      _ <- isTrue(parsedJwsWithKey2Payload == payload, Error("parsedPayload2 must equal")).eLiftET[IO]
    yield
      ()

  def testBadKeyOnSign(alg: JWSAlgorithm, key: Option[Key] = None, provider: Option[Provider | JProvider] = None)
  : IO[Boolean] =
      JsonWebSignature.signString[IO](JoseHeader(Some(alg)), "whatever", key).map(_.isLeft)

  def testBadKeyOnVerify(compact: String, key: Option[Key] = None, provider: Option[Provider | JProvider] = None)
  : EitherT[IO, Error, Unit] =
    for
      jws <- JsonWebSignature.parse(compact).eLiftET[IO]
      _ <- EitherT(jws.check[IO](key, provider = provider).map(_.swap.asError))
    yield
      ()
end JsonWebSignatureTestOps
