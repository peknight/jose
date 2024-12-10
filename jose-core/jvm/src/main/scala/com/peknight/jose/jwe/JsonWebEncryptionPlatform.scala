package com.peknight.jose.jwe

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Async
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.{Id, Monad}
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET}
import com.peknight.codec.Decoder
import com.peknight.codec.cursor.Cursor
import com.peknight.error.Error
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.jose.jwx.{JoseConfiguration, bytesDecodeToJson, bytesDecodeToString, stringEncodeToBytes}
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.StandardCharsets
import java.security.Key

trait JsonWebEncryptionPlatform { self: JsonWebEncryption =>

  def decrypt[F[_]: Async: Compression](key: Key, configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, ByteVector]] =
    val eitherT =
      for
        encryptedKey <- EitherT(self.encryptedKey.decode[F])
        initializationVector <- EitherT(self.initializationVector.decode[F])
        ciphertext <- EitherT(self.ciphertext.decode[F])
        authenticationTag <- EitherT(self.authenticationTag.decode[F])
        additionalAuthenticatedData <- getAdditionalAuthenticatedData.eLiftET
        header <- self.getMergedHeader.eLiftET
        _ <- header.checkCritical(configuration.knownCriticalHeaders).eLiftET
        res <- EitherT(JsonWebEncryption.handleDecrypt[F](header, key, encryptedKey, initializationVector, ciphertext,
          authenticationTag, additionalAuthenticatedData, configuration))
      yield
        res
    eitherT.value

  def decryptString[F[_]: Async: Compression](key: Key,
                                              configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, String]] =
    handleDecrypt[F, String](key, configuration)(bytes => bytesDecodeToString(bytes, configuration.charset))

  def decryptJson[F[_], A](key: Key, configuration: JoseConfiguration = JoseConfiguration.default)
                          (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A]): F[Either[Error, A]] =
    handleDecrypt[F, A](key, configuration)(bytes => bytesDecodeToJson[A](bytes, configuration.charset))

  private def handleDecrypt[F[_]: Async: Compression, A](key: Key,
                                                         configuraion: JoseConfiguration = JoseConfiguration.default)
                                                        (f: ByteVector => Either[Error, A])
  : F[Either[Error, A]] =
    decrypt[F](key, configuraion).map(_.flatMap(f))


  def getPayloadBytes[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
                                               (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                               (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, ByteVector]] =
    handleGetPayload[F, ByteVector](configuration)(decryptionPrimitivesF)(decrypt[F])

  def getPayloadString[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
                                                (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, String]] =
    handleGetPayload[F, String](configuration)(decryptionPrimitivesF)(decryptString[F])

  def getPayloadJson[F[_], A](configuration: JoseConfiguration = JoseConfiguration.default)
                             (verificationPrimitivesF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                             (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    handleGetPayload[F, A](configuration)(decryptionPrimitivesF)(decryptJson[F, A])


  private def handleGetPayload[F[_]: Async: Compression, A](configuration: JoseConfiguration = JoseConfiguration.default)
                                                           (decryptionPrimitivesF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                                                           (decrypt: (Key, JoseConfiguration) => F[Either[Error, A]])
  : F[Either[Error, A]] =
    val eitherT =
      for
        primitives <- EitherT(decryptionPrimitivesF(self, configuration))
        payload <- EitherT(handleDecryptWithPrimitives(primitives)(decrypt))
      yield
        payload
    eitherT.value

  private def handleDecryptWithPrimitives[F[_]: Async: Compression, A](primitives: NonEmptyList[DecryptionPrimitive])
                                                                      (decrypt: (Key, JoseConfiguration) => F[Either[Error, A]])
  : F[Either[Error, A]] =
    decrypt(primitives.head.key, primitives.head.configuration).flatMap {
      case Right(value) => value.asRight[Error].pure[F]
      case Left(error) => Monad[[X] =>> EitherT[F, Error, X]].tailRecM[List[DecryptionPrimitive], A](primitives.tail) {
        case head :: tail => EitherT(decrypt(head.key, head.configuration).map {
          case Right(value) => value.asRight[List[DecryptionPrimitive]].asRight[Error]
          case Left(error) => tail.asLeft[A].asRight[Error]
        })
        case Nil => error.lLiftET[F, Either[List[DecryptionPrimitive], A]]
      }.value
    }

  private def getAdditionalAuthenticatedData: Either[Error, ByteVector] =
    self.additionalAuthenticatedData
      .fold(getProtectedHeader)(_.asRight)
      .flatMap(base => stringEncodeToBytes(base.value, StandardCharsets.US_ASCII))
}
