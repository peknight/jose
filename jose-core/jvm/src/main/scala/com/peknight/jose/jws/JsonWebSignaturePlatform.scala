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
import com.peknight.jose.jwx.JoseConfig
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.Charset
import java.security.Key

trait JsonWebSignaturePlatform { self: JsonWebSignature =>
  def verify[F[_]: Sync](key: Option[Key] = None, config: JoseConfig = JoseConfig.default)
  : F[Either[Error, Boolean]] =
    val either =
      for
        h <- self.getUnprotectedHeader
        p <- self.getProtectedHeader
        data <- JsonWebSignature.toBytes(p, self.payload, config.charset)
        signed <- self.signature.decode[Id]
        _ <- h.checkCritical(base64UrlEncodePayloadLabel :: config.knownCriticalHeaders)
      yield
        JsonWebSignature.handleVerify[F](h.algorithm, key, data, signed, config)
    either.fold(_.asLeft.pure, identity)

  def check[F[_]: Sync](key: Option[Key] = None, config: JoseConfig = JoseConfig.default)
  : F[Either[Error, Unit]] =
    JsonWebSignature.checkVerify(verify[F](key, config))

  def checkWithPrimitives[F[_]: Sync](primitives: NonEmptyList[VerificationPrimitive])
  : F[Either[Error, VerificationPrimitive]] =
    check[F](primitives.head.key, primitives.head.config).flatMap {
      case Right(_) => primitives.head.asRight[Error].pure[F]
      case Left(error) =>
        Monad[[X] =>> EitherT[F, Error, X]].tailRecM[List[VerificationPrimitive], VerificationPrimitive](primitives.tail) {
          case head :: tail => EitherT(check(head.key, head.config).map {
            case Right(_) => head.asRight[List[VerificationPrimitive]].asRight[Error]
            case Left(_) => tail.asLeft[VerificationPrimitive].asRight[Error]
          })
          case Nil => error.lLiftET[F, Either[List[VerificationPrimitive], VerificationPrimitive]]
        }.value
    }

  def verifiedPayloadBytes[F[_]: Sync](key: Option[Key] = None,
                                       config: JoseConfig = JoseConfig.default)
  : F[Either[Error, ByteVector]] =
    handleVerifiedPayload[F, ByteVector](key, config)(decodePayload)

  def verifiedPayloadString[F[_]: Sync](key: Option[Key] = None,
                                        config: JoseConfig = JoseConfig.default)
  : F[Either[Error, String]] =
    handleVerifiedPayload[F, String](key, config)(decodePayloadString)

  def verifiedPayloadJson[F[_], A](key: Option[Key] = None,
                                   config: JoseConfig = JoseConfig.default)
                                  (using Sync[F], Decoder[Id, Cursor[Json], A]): F[Either[Error, A]] =
    handleVerifiedPayload[F, A](key, config)(decodePayloadJson[A])

  private def handleVerifiedPayload[F[_], A](key: Option[Key] = None,
                                             config: JoseConfig = JoseConfig.default)
                                            (decodePayload: Charset => Either[Error, A])
                                            (using Sync[F]): F[Either[Error, A]] =
    check[F](key, config).map(_.flatMap(_ => decodePayload(config.charset)))

  def getPayloadBytes[F[_]: {Async, Compression}](config: JoseConfig = JoseConfig.default)
                                                 (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                 (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, ByteVector]] =
    handleGetPayload[F, ByteVector](config)(verificationPrimitivesF)(decodePayload)

  def getPayloadString[F[_]: {Async, Compression}](config: JoseConfig = JoseConfig.default)
                                                  (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                  (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, String]] =
    handleGetPayload[F, String](config)(verificationPrimitivesF)(decodePayloadString)

  def getPayloadJson[F[_], A](config: JoseConfig = JoseConfig.default)
                             (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                             (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    handleGetPayload[F, A](config)(verificationPrimitivesF)(decodePayloadJson[A])

  private def handleGetPayload[F[_]: Sync, A](config: JoseConfig = JoseConfig.default)
                                             (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                             (decodePayload: Charset => Either[Error, A])
  : F[Either[Error, A]] =
    if config.skipSignatureVerification then decodePayload(config.charset).pure[F] else
      val eitherT =
        for
          header <- getUnprotectedHeader.eLiftET[F]
          noneAlg = header.isNoneAlgorithm
          primitives <-
            if noneAlg && config.skipVerificationKeyResolutionOnNone then
              NonEmptyList.one(VerificationPrimitive(None, config)).rLiftET[F, Error]
            else EitherT(verificationPrimitivesF(self, config))
          payload <- EitherT(handleGetPayloadWithPrimitives[F, A](primitives)(decodePayload))
        yield
          payload
      eitherT.value

  private def handleGetPayloadWithPrimitives[F[_]: Sync, A](primitives: NonEmptyList[VerificationPrimitive])
                                                           (decodePayload: Charset => Either[Error, A])
  : F[Either[Error, A]] =
    checkWithPrimitives[F](primitives).map(_.flatMap(primitive => decodePayload(primitive.config.charset)))
}
