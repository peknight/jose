package com.peknight.jose.jws

import cats.Id
import cats.data.EitherT
import cats.effect.{Async, Sync}
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, rLiftET}
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
                                               (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                               (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
  : F[Either[Error, ByteVector]] =
    handleGetPayload[F, ByteVector](configuration)(verificationPrimitiveF)(decodePayload)

  def getPayloadString[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
                                                (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                                (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
  : F[Either[Error, String]] =
    handleGetPayload[F, String](configuration)(verificationPrimitiveF)(decodePayloadString)

  def getPayloadJson[F[_], A](configuration: JoseConfiguration = JoseConfiguration.default)
                             (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                             (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    handleGetPayload[F, A](configuration)(verificationPrimitiveF)(decodePayloadJson[A])

  private def handleGetPayload[F[_]: Sync, A](configuration: JoseConfiguration = JoseConfiguration.default)
                                             (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                             (decodePayload: Charset => Either[Error, A])
  : F[Either[Error, A]] =
    if configuration.skipSignatureVerification then decodePayload(configuration.charset).pure[F] else
      val eitherT =
        for
          header <- getUnprotectedHeader.eLiftET[F]
          noneAlg = header.isNoneAlgorithm
          primitive <-
            if noneAlg && configuration.skipVerificationKeyResolutionOnNone then
              VerificationPrimitive(None, configuration).rLiftET[F, Error]
            else EitherT(verificationPrimitiveF(self, configuration))
          payload <- EitherT(handleVerifiedPayload[F, A](primitive.key, primitive.configuration)(decodePayload))
        yield
          payload
      eitherT.value
}
