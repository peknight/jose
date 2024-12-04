package com.peknight.jose.jwx

import cats.Id
import cats.data.EitherT
import cats.effect.Async
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET, rLiftET}
import com.peknight.codec.Decoder
import com.peknight.codec.cursor.Cursor
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.UnsupportedJsonWebStructure
import com.peknight.jose.jwa.encryption.KeyDecipherMode
import com.peknight.jose.jwa.signature.none
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.security.provider.Provider
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebStructurePlatform { self: JsonWebStructure =>
//   def getPayloadBytes[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
//                                                (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
//                                                (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
//   : F[Either[Error, ByteVector]] =
//     val eitherT =
//       self match
//         case jwe: JsonWebEncryption =>
//           for
//             primitive <- EitherT(decryptionPrimitiveF(jwe, configuration))
//             payload <- EitherT(jwe.decrypt[F](primitive.managementKey, primitive.configuration))
//           yield
//             payload
//         case jws: JsonWebSignature =>
//           if configuration.skipSignatureVerification then jws.decodePayload(configuration.charset).eLiftET[F]
//           else
//             for
//               header <- jws.getUnprotectedHeader.eLiftET[F]
//               noneAlg = header.algorithm.contains(none)
//               primitive <-
//                 if noneAlg && configuration.skipVerificationKeyResolutionOnNone then
//                   VerificationPrimitive(None, configuration).rLiftET[F, Error]
//                 else EitherT(verificationPrimitiveF(jws, configuration))
//               _ <- EitherT(jws.check[F](primitive.key, primitive.configuration))
//               payload <- jws.decodePayload(primitive.configuration.charset).eLiftET[F]
//             yield
//               payload
//         case _ => UnsupportedJsonWebStructure(self).lLiftET[F, ByteVector]
//     eitherT.value
//
//   def getPayloadString[F[_]: Async: Compression](configuration: JoseConfiguration = JoseConfiguration.default)
//                                                 (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
//                                                 (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
//   : F[Either[Error, String]] =
//     doHandleGetPayload[F, String](configuration)(verificationPrimitiveF)(decryptionPrimitiveF)(bytes => bytesDecodeToString(bytes, configuration.charset))
//
//   def getPayloadJson[F[_], A](configuration: JoseConfiguration = JoseConfiguration.default)
//                              (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
//                              (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
//                              (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
//   : F[Either[Error, A]] =
//     doHandleGetPayload[F, A](configuration)(verificationPrimitiveF)(decryptionPrimitiveF)(bytes => bytesDecodeToJson[A](bytes, configuration.charset))
//
//   private def doHandleGetPayload[F[_]: Async: Compression, A](configuration: JoseConfiguration = JoseConfiguration.default)
//                                                              (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
//                                                              (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
//                                                              (decode: ByteVector => Either[Error, A])
//   : F[Either[Error, A]] =
//     getPayloadBytes[F](configuration)(verificationPrimitiveF)(decryptionPrimitiveF).map(_.flatMap(decode))
}
