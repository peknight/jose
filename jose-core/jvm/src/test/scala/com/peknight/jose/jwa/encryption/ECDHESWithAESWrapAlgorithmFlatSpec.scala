package com.peknight.jose.jwa.encryption

import cats.Id
import cats.data.EitherT
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.effect.{IO, Sync}
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwk.JsonWebKey.EllipticCurveJsonWebKey
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.error.PointNotOnCurve
import org.scalatest.Assertion
import org.scalatest.flatspec.AsyncFlatSpec

class ECDHESWithAESWrapAlgorithmFlatSpec extends AsyncFlatSpec with AsyncIOSpec:

  "ECDH-ESWithAESWrap" should "succeed with round trip" in {
    val run =
      for
        algs <- filterAvailableAlgorithms[IO, `ECDH-ESWithAESWrapAlgorithm`](`ECDH-ESWithAESWrapAlgorithm`.values)
        encs <- filterAvailableAlgorithms[IO, AESCBCHmacSHA2Algorithm](AESCBCHmacSHA2Algorithm.values)
        tests =
          for
            alg <- algs
            enc <- encs
          yield jweRoundTrip(alg, enc)
        res <- tests.sequence.value.map(_.map(_.forall(identity)).getOrElse(false))
      yield
        res
    run.asserting(assert)
  }

  private def filterAvailableAlgorithms[F[_]: Sync, A <: AlgorithmIdentifier](algorithms: List[A]): F[List[A]] =
    algorithms.traverse[F, Option[A]](alg => alg.isAvailable[F].map(available => if available then alg.some else none))
      .map(_.collect {
        case Some(alg) => alg
      })

  private def jweRoundTrip(alg: `ECDH-ESWithAESWrapAlgorithm`, enc: AESCBCHmacSHA2Algorithm)
  : EitherT[IO, Error, Boolean] =
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_" +
      "PxMQ\",\n \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFAS" +
      "Rl6BfUqdw\"\n}"
    val plaintext = "Gambling is illegal at Bushwood sir, and I never slice."
    for
      receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
      receiverPublicKey <- EitherT(receiverJwk.toPublicKey[IO]())
      receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
      jwe <- EitherT(JsonWebEncryption.encryptString[IO](receiverPublicKey, plaintext, JoseHeader(Some(alg), Some(enc))))
      jweCompact <- jwe.compact.eLiftET[IO]
      receiverJwe <- JsonWebEncryption.parse(jweCompact).eLiftET[IO]
      res <- EitherT(receiverJwe.decryptString[IO](receiverPrivateKey))
    yield
      res == plaintext

  "ECDH-ES+A128KW" should "failed with invalid curve 1" in {
    val maliciousJweCompact = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiL" +
      "CJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TU" +
      "c3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX30" +
      "4PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYF" +
      "ecyDvuUa43KKT6w"
    pointNotOnCurve(maliciousJweCompact)
  }

  "ECDH-ES+A128KW" should "failed with invalid curve 2" in {
    val maliciousJweCompact = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiL" +
      "CJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTn" +
      "c3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oM" +
      "ob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7" +
      "FcvA5MIOq-Pkj8A"
    pointNotOnCurve(maliciousJweCompact)
  }

  private def pointNotOnCurve(maliciousJweCompact: String): IO[Assertion] =
    val receiverJwkJson = "\n{\"kty\":\"EC\",\n \"crv\":\"P-256\",\n \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_" +
      "PxMQ\",\n \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFAS" +
      "Rl6BfUqdw\"\n}"
    val run =
      for
        receiverJwk <- decode[Id, EllipticCurveJsonWebKey](receiverJwkJson).eLiftET[IO]
        receiverPrivateKey <- EitherT(receiverJwk.toPrivateKey[IO]())
        maliciousJwe <- JsonWebEncryption.parse(maliciousJweCompact).eLiftET[IO]
        res <- EitherT(maliciousJwe.decryptString[IO](receiverPrivateKey))
      yield
        true
    run.value.map {
      case Left(e: PointNotOnCurve) => true
      case _ => false
    }.asserting(assert)

end ECDHESWithAESWrapAlgorithmFlatSpec
