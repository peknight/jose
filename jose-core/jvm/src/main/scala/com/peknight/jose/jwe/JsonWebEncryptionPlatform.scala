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
import com.peknight.jose.jwe.JsonWebEncryption.handleDecrypt
import com.peknight.jose.jwx.{JoseConfiguration, bytesDecodeToJson, bytesDecodeToString, stringEncodeToBytes}
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.StandardCharsets
import java.security.Key

trait JsonWebEncryptionPlatform { self: JsonWebEncryption =>

  def decrypt[F[_]: Async: Compression](managementKey: Key,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, ByteVector]] =
    val eitherT =
      for
        encryptedKey <- EitherT(self.encryptedKey.decode[F])
        initializationVector <- EitherT(self.initializationVector.decode[F])
        ciphertext <- EitherT(self.ciphertext.decode[F])
        authenticationTag <- EitherT(self.authenticationTag.decode[F])
        additionalAuthenticatedData <- getAdditionalAuthenticatedData.eLiftET
        header <- self.getUnprotectedHeader.eLiftET
        _ <- header.checkCritical(configuration.knownCriticalHeaders).eLiftET
        res <- EitherT(handleDecrypt[F](managementKey, encryptedKey, initializationVector, ciphertext,
          authenticationTag, additionalAuthenticatedData, header, configuration))
      yield
        res
    eitherT.value

  def decryptString[F[_]: Async: Compression](managementKey: Key,
                                              configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, String]] =
    doHandleDecrypt[F, String](managementKey, configuration)(bytes => bytesDecodeToString(bytes, configuration.charset))

  def decryptJson[F[_], A](managementKey: Key, configuration: JoseConfiguration = JoseConfiguration.default)
                          (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A]): F[Either[Error, A]] =
    doHandleDecrypt[F, A](managementKey, configuration)(bytes => bytesDecodeToJson[A](bytes, configuration.charset))

  private def doHandleDecrypt[F[_]: Async: Compression, A](managementKey: Key,
                                                           configuraion: JoseConfiguration = JoseConfiguration.default)
                                                          (f: ByteVector => Either[Error, A])
  : F[Either[Error, A]] =
    decrypt[F](managementKey, configuraion).map(_.flatMap(f))

  private def getAdditionalAuthenticatedData: Either[Error, ByteVector] =
    self.additionalAuthenticatedData
      .fold(getProtectedHeader)(_.asRight)
      .flatMap(base => stringEncodeToBytes(base.value, StandardCharsets.US_ASCII))
}
