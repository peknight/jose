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
import com.peknight.jose.jwx.{JoseConfig, bytesDecodeToJson, bytesDecodeToString, stringEncodeToBytes}
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import java.security.Key

trait JsonWebEncryptionPlatform { self: JsonWebEncryption =>

  def decrypt[F[_]: {Async, Compression}](key: Key, config: JoseConfig = JoseConfig.default)
  : F[Either[Error, ByteVector]] =
    val eitherT =
      for
        encryptedKey <- EitherT(self.encryptedKey.decode[F])
        initializationVector <- EitherT(self.initializationVector.decode[F])
        ciphertext <- EitherT(self.ciphertext.decode[F])
        authenticationTag <- EitherT(self.authenticationTag.decode[F])
        additionalAuthenticatedData <- getAdditionalAuthenticatedData.eLiftET
        header <- self.getMergedHeader.eLiftET
        _ <- header.checkCritical(config.knownCriticalHeaders).eLiftET
        res <- EitherT(JsonWebEncryption.handleDecrypt[F](header, key, encryptedKey, initializationVector, ciphertext,
          authenticationTag, additionalAuthenticatedData, config))
      yield
        res
    eitherT.value

  def decryptWithPrimitives[F[_]: {Async, Compression}](primitives: NonEmptyList[DecryptionPrimitive])
  : F[Either[Error, (ByteVector, DecryptionPrimitive)]] =
    decrypt(primitives.head.key, primitives.head.config).flatMap {
      case Right(value) => (value, primitives.head).asRight[Error].pure[F]
      case Left(error) =>
        Monad[[X] =>> EitherT[F, Error, X]].tailRecM[List[DecryptionPrimitive], (ByteVector, DecryptionPrimitive)](
          primitives.tail
        ) {
          case head :: tail => EitherT(decrypt(head.key, head.config).map {
            case Right(value) => (value, head).asRight[List[DecryptionPrimitive]].asRight[Error]
            case Left(error) => tail.asLeft[(ByteVector, DecryptionPrimitive)].asRight[Error]
          })
          case Nil => error.lLiftET[F, Either[List[DecryptionPrimitive], (ByteVector, DecryptionPrimitive)]]
        }.value
    }

  def decryptString[F[_]: {Async, Compression}](key: Key,
                                                config: JoseConfig = JoseConfig.default)
  : F[Either[Error, String]] =
    handleDecrypt[F, String](key, config)(bytes => bytesDecodeToString(bytes, config.charset))

  def decryptJson[F[_], A](key: Key, config: JoseConfig = JoseConfig.default)
                          (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A]): F[Either[Error, A]] =
    handleDecrypt[F, A](key, config)(bytes => bytesDecodeToJson[A](bytes, config.charset))

  private def handleDecrypt[F[_]: {Async, Compression}, A](key: Key,
                                                           configuraion: JoseConfig = JoseConfig.default)
                                                          (f: ByteVector => Either[Error, A])
  : F[Either[Error, A]] =
    decrypt[F](key, configuraion).map(_.flatMap(f))

  def decryptStringWithPrimitives[F[_]: {Async, Compression}](primitives: NonEmptyList[DecryptionPrimitive])
  : F[Either[Error, (String, DecryptionPrimitive)]] =
    handleDecryptWithPrimitives[F, String](primitives)(bytesDecodeToString)

  def decryptJsonWithPrimitives[F[_], A](primitives: NonEmptyList[DecryptionPrimitive])
                                        (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, (A, DecryptionPrimitive)]] =
    handleDecryptWithPrimitives[F, A](primitives)(bytesDecodeToJson[A])

  private def handleDecryptWithPrimitives[F[_]: {Async, Compression}, A](primitives: NonEmptyList[DecryptionPrimitive])
                                                                        (f: (ByteVector, Charset) => Either[Error, A])
  : F[Either[Error, (A, DecryptionPrimitive)]] =
    decryptWithPrimitives[F](primitives).map(_.flatMap(
      (bytes, primitive) => f(bytes, primitive.config.charset).map((_, primitive))
    ))

  def getPayloadBytes[F[_]: {Async, Compression}](config: JoseConfig = JoseConfig.default)
                                                 (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                 (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, ByteVector]] =
    val eitherT =
      for
        primitives <- EitherT(decryptionPrimitivesF(self, config))
        payload <- EitherT(decryptWithPrimitives(primitives))
      yield
        payload._1
    eitherT.value

  def getPayloadString[F[_]: {Async, Compression}](config: JoseConfig = JoseConfig.default)
                                                  (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                  (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, String]] =
    handleGetPayload[F, String](config)(decryptionPrimitivesF)(bytesDecodeToString)

  def getPayloadJson[F[_], A](config: JoseConfig = JoseConfig.default)
                             (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                             (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    handleGetPayload[F, A](config)(decryptionPrimitivesF)(bytesDecodeToJson[A])

  private def handleGetPayload[F[_]: {Async, Compression}, A](config: JoseConfig = JoseConfig.default)
                                                             (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                                                             (f: (ByteVector, Charset) => Either[Error, A])
  : F[Either[Error, A]] =
    val eitherT =
      for
        primitives <- EitherT(decryptionPrimitivesF(self, config))
        payload <- EitherT(handleDecryptWithPrimitives(primitives)(f))
      yield
        payload._1
    eitherT.value

  private def getAdditionalAuthenticatedData: Either[Error, ByteVector] =
    self.additionalAuthenticatedData match
      case Some(value) => value.decode[Id]
      case None => getProtectedHeader.flatMap(base => stringEncodeToBytes(base.value, StandardCharsets.US_ASCII))
}
