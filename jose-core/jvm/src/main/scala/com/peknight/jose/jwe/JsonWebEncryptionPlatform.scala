package com.peknight.jose.jwe

import cats.Id
import cats.data.EitherT
import cats.effect.Async
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
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
                                               (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                               (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
  : F[Either[Error, ByteVector]] =
    handleGetPayload[F, ByteVector](configuration)(decryptionPrimitiveF)(decrypt[F])

  def getPayloadString[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
                                                (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                                (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
  : F[Either[Error, String]] =
    handleGetPayload[F, String](configuration)(decryptionPrimitiveF)(decryptString[F])

  def getPayloadJson[F[_], A](configuration: JoseConfiguration = JoseConfiguration.default)
                             (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                             (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    handleGetPayload[F, A](configuration)(decryptionPrimitiveF)(decryptJson[F, A])


  private def handleGetPayload[F[_]: Async: Compression, A](configuration: JoseConfiguration = JoseConfiguration.default)
                                                           (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
                                                           (decrypt: (Key, JoseConfiguration) => F[Either[Error, A]])
  : F[Either[Error, A]] =
    val eitherT =
      for
        primitive <- EitherT(decryptionPrimitiveF(self, configuration))
        payload <- EitherT(decrypt(primitive.key, primitive.configuration))
      yield
        payload
    eitherT.value

  private def getAdditionalAuthenticatedData: Either[Error, ByteVector] =
    self.additionalAuthenticatedData
      .fold(getProtectedHeader)(_.asRight)
      .flatMap(base => stringEncodeToBytes(base.value, StandardCharsets.US_ASCII))
}
