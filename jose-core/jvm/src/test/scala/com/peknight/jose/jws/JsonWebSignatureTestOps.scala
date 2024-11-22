package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.signature.JWSAlgorithm
import com.peknight.jose.jwx.JoseHeader
import com.peknight.validation.std.either.isTrue

import java.security.Key

object JsonWebSignatureTestOps:
  def testBasicRoundTrip(payload: String, jwsAlgo: JWSAlgorithm,
                         signingKey1: Key, verificationKey1: Key,
                         signingKey2: Key, verificationKey2: Key): EitherT[IO, Error, Unit] =
    for
      jwsWithKey1 <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(jwsAlgo)), payload, Some(signingKey1)))
      jwsWithKey2 <- EitherT(JsonWebSignature.signUtf8[IO](JoseHeader(Some(jwsAlgo)), payload, Some(signingKey2)))
      serializationWithKey1 <- jwsWithKey1.compact.eLiftET[IO]
      serializationWithKey2 <- jwsWithKey2.compact.eLiftET[IO]
      parsedJwsWithKey1 <- JsonWebSignature.parse(serializationWithKey1).asError.eLiftET[IO]
      parsedJwsWithKey2 <- JsonWebSignature.parse(serializationWithKey2).asError.eLiftET[IO]
      jwsWithKey1Payload <- jwsWithKey1.decodePayloadUtf8.eLiftET[IO]
      jwsWithKey2Payload <- jwsWithKey2.decodePayloadUtf8.eLiftET[IO]
      parsedJwsWithKey1Payload <- parsedJwsWithKey1.decodePayloadUtf8.eLiftET[IO]
      parsedJwsWithKey2Payload <- parsedJwsWithKey2.decodePayloadUtf8.eLiftET[IO]
      _ <- isTrue(serializationWithKey1 != serializationWithKey2, Error("compact cannot equal")).eLiftET[IO]
      _ <- EitherT(parsedJwsWithKey1.check[IO](Some(verificationKey1)))
      _ <- EitherT(parsedJwsWithKey2.check[IO](Some(verificationKey2)))
      _ <- EitherT(parsedJwsWithKey1.check[IO](Some(verificationKey2)).map(_.swap.asError))
      _ <- EitherT(parsedJwsWithKey2.check[IO](Some(verificationKey1)).map(_.swap.asError))
      _ <- isTrue(jwsWithKey1Payload == payload, Error("payload1 must equal")).eLiftET[IO]
      _ <- isTrue(jwsWithKey2Payload == payload, Error("payload2 must equal")).eLiftET[IO]
      _ <- isTrue(parsedJwsWithKey1Payload == payload, Error("parsedPayload1 must equal")).eLiftET[IO]
      _ <- isTrue(parsedJwsWithKey2Payload == payload, Error("parsedPayload2 must equal")).eLiftET[IO]
    yield
      ()
end JsonWebSignatureTestOps
