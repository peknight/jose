package com.peknight.jose.jwx

import cats.Id
import cats.data.NonEmptyList
import cats.effect.Async
import com.peknight.codec.Decoder
import com.peknight.codec.cursor.Cursor
import com.peknight.error.Error
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

trait JsonWebStructurePlatform { self: JsonWebStructure =>
  def getPayloadBytes[F[_]: {Async, Compression}](config: JoseConfig = JoseConfig.default)
                                                 (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                 (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, ByteVector]]

  def getPayloadString[F[_]: {Async, Compression}](config: JoseConfig = JoseConfig.default)
                                                  (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                                                  (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
  : F[Either[Error, String]]

  def getPayloadJson[F[_], A](config: JoseConfig = JoseConfig.default)
                             (verificationPrimitivesF: (JsonWebSignature, JoseConfig) => F[Either[Error, NonEmptyList[VerificationPrimitive]]])
                             (decryptionPrimitivesF: (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A]): F[Either[Error, A]]
}
