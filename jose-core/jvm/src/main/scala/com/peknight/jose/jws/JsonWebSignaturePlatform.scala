package com.peknight.jose.jws

import cats.data.{EitherT, NonEmptyList}
import cats.effect.{Async, Sync}
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.{Id, Monad}
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET, rLiftET}
import com.peknight.codec.Decoder
import com.peknight.codec.cursor.Cursor
import com.peknight.error.Error
import com.peknight.jose.base64UrlEncodePayloadLabel
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jwx.JoseConfiguration
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.Charset
import java.security.Key

trait JsonWebSignaturePlatform { self: JsonWebSignature =>
  def verify[F[_]: Sync](key: Option[Key] = None, configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, Boolean]] =
    val either =
      for
        h <- self.getUnprotectedHeader
        p <- self.getProtectedHeader
        data <- JsonWebSignature.toBytes(p, self.payload, configuration.charset)
        signed <- self.signature.decode[Id]
        _ <- h.checkCritical(base64UrlEncodePayloadLabel :: configuration.knownCriticalHeaders)
      yield
        JsonWebSignature.handleVerify[F](h.algorithm, key, data, signed, configuration)
    either.fold(_.asLeft.pure, identity)

  def check[F[_]: Sync](key: Option[Key] = None, configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(verify[F](key, configuration))

  def verifiedPayloadBytes[F[_]: Sync](key: Option[Key] = None,
                                       configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, ByteVector]] =
    handleVerifiedPayload[F, ByteVector](key, configuration)(decodePayload)

  def verifiedPayloadString[F[_]: Sync](key: Option[Key] = None,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, String]] =
    handleVerifiedPayload[F, String](key, configuration)(decodePayloadString)

  def verifiedPayloadJson[F[_], A](key: Option[Key] = None,
                                   configuration: JoseConfiguration = JoseConfiguration.default)
                                  (using Sync[F], Decoder[Id, Cursor[Json], A]): F[Either[Error, A]] =
    handleVerifiedPayload[F, A](key, configuration)(decodePayloadJson[A])

  private def handleVerifiedPayload[F[_], A](key: Option[Key] = None,
                                             configuration: JoseConfiguration = JoseConfiguration.default)
                                            (decodePayload: Charset => Either[Error, A])
                                            (using Sync[F]): F[Either[Error, A]] =
    check[F](key, configuration).map(_.flatMap(_ => decodePayload(configuration.charset)))

  def getPayloadBytes[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
                                               (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                               (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, ByteVector]] =
    handleGetPayload[F, ByteVector](configuration)(verificationPrimitivesF)(decodePayload)

  def getPayloadString[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
                                                (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, String]] =
    handleGetPayload[F, String](configuration)(verificationPrimitivesF)(decodePayloadString)

  def getPayloadJson[F[_], A](configuration: JoseConfiguration = JoseConfiguration.default)
                             (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                             (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    handleGetPayload[F, A](configuration)(verificationPrimitivesF)(decodePayloadJson[A])

  private def handleGetPayload[F[_]: Sync, A](configuration: JoseConfiguration = JoseConfiguration.default)
                                             (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                             (decodePayload: Charset => Either[Error, A])
  : F[Either[Error, A]] =
    if configuration.skipSignatureVerification then decodePayload(configuration.charset).pure[F] else
      val eitherT =
        for
          header <- getUnprotectedHeader.eLiftET[F]
          noneAlg = header.isNoneAlgorithm
          primitives <-
            if noneAlg && configuration.skipVerificationKeyResolutionOnNone then
              NonEmptyList.one(VerificationPrimitive(None, configuration)).rLiftET[F, Error]
            else EitherT(verificationPrimitivesF(self, configuration))
          payload <- EitherT(handleGetPayloadWithPrimitives[F, A](primitives)(decodePayload))
        yield
          payload
      eitherT.value

  private def handleGetPayloadWithPrimitives[F[_]: Sync, A](primitives: NonEmptyList[VerificationPrimitive])
                                                           (decodePayload: Charset => Either[Error, A])
  : F[Either[Error, A]] =
    handleVerifiedPayload[F, A](primitives.head.key, primitives.head.configuration)(decodePayload).flatMap {
      case Right(value) => value.asRight[Error].pure[F]
      case Left(error) => Monad[[X] =>> EitherT[F, Error, X]].tailRecM[List[VerificationPrimitive], A](primitives.tail) {
        case head :: tail => EitherT(handleVerifiedPayload(head.key, head.configuration)(decodePayload).map {
          case Right(value) => value.asRight[List[VerificationPrimitive]].asRight[Error]
          case Left(error) => tail.asLeft[A].asRight[Error]
        })
        case Nil => error.lLiftET[F, Either[List[VerificationPrimitive], A]]
      }.value
    }
}
