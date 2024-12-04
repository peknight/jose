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
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.security.provider.Provider
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebStructurePlatform { self: JsonWebStructure =>
  def getPayloadJson[F[_], A](skipSignatureVerification: Boolean = false,
                              skipVerificationKeyResolutionOnNone: Boolean = false,
                              knownCriticalHeaders: List[String] = List.empty[String],
                              doKeyValidation: Boolean = true,
                              useLegacyName: Boolean = false,
                              keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                              random: Option[SecureRandom] = None,
                              cipherProvider: Option[Provider | JProvider] = None,
                              keyAgreementProvider: Option[Provider | JProvider] = None,
                              keyFactoryProvider: Option[Provider | JProvider] = None,
                              macProvider: Option[Provider | JProvider] = None,
                              messageDigestProvider: Option[Provider | JProvider] = None,
                              signatureProvider: Option[Provider | JProvider] = None)
                             (verificationKey: JsonWebSignature => F[Either[Error, Option[Key]]])
                             (decryptionKey: JsonWebEncryption => F[Either[Error, Key]])
                             (using Async[F], Compression[F], Decoder[Id, Cursor[Json], A])
  : F[Either[Error, A]] =
    getPayloadBytes[F](skipSignatureVerification, skipVerificationKeyResolutionOnNone, knownCriticalHeaders,
      doKeyValidation, useLegacyName, keyDecipherModeOverride, random, cipherProvider, keyAgreementProvider,
      keyFactoryProvider, macProvider, messageDigestProvider, signatureProvider
    )(verificationKey)(decryptionKey).map(_.flatMap(bytesDecodeToJson[A]))

  def getPayloadUtf8[F[_]:Async: Compression](skipSignatureVerification: Boolean = false,
                                              skipVerificationKeyResolutionOnNone: Boolean = false,
                                              knownCriticalHeaders: List[String] = List.empty[String],
                                              doKeyValidation: Boolean = true,
                                              useLegacyName: Boolean = false,
                                              keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                                              random: Option[SecureRandom] = None,
                                              cipherProvider: Option[Provider | JProvider] = None,
                                              keyAgreementProvider: Option[Provider | JProvider] = None,
                                              keyFactoryProvider: Option[Provider | JProvider] = None,
                                              macProvider: Option[Provider | JProvider] = None,
                                              messageDigestProvider: Option[Provider | JProvider] = None,
                                              signatureProvider: Option[Provider | JProvider] = None)
                                             (verificationKey: JsonWebSignature => F[Either[Error, Option[Key]]])
                                             (decryptionKey: JsonWebEncryption => F[Either[Error, Key]])
  : F[Either[Error, String]] =
    getPayloadString[F](StandardCharsets.UTF_8, skipSignatureVerification, skipVerificationKeyResolutionOnNone,
      knownCriticalHeaders, doKeyValidation, useLegacyName, keyDecipherModeOverride, random, cipherProvider,
      keyAgreementProvider, keyFactoryProvider, macProvider, messageDigestProvider, signatureProvider
    )(verificationKey)(decryptionKey)

  def getPayloadString[F[_]:Async: Compression](charset: Charset = StandardCharsets.UTF_8,
                                                skipSignatureVerification: Boolean = false,
                                                skipVerificationKeyResolutionOnNone: Boolean = false,
                                                knownCriticalHeaders: List[String] = List.empty[String],
                                                doKeyValidation: Boolean = true,
                                                useLegacyName: Boolean = false,
                                                keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                                                random: Option[SecureRandom] = None,
                                                cipherProvider: Option[Provider | JProvider] = None,
                                                keyAgreementProvider: Option[Provider | JProvider] = None,
                                                keyFactoryProvider: Option[Provider | JProvider] = None,
                                                macProvider: Option[Provider | JProvider] = None,
                                                messageDigestProvider: Option[Provider | JProvider] = None,
                                                signatureProvider: Option[Provider | JProvider] = None)
                                               (verificationKey: JsonWebSignature => F[Either[Error, Option[Key]]])
                                               (decryptionKey: JsonWebEncryption => F[Either[Error, Key]])
  : F[Either[Error, String]] =
    getPayloadBytes[F](skipSignatureVerification, skipVerificationKeyResolutionOnNone, knownCriticalHeaders,
      doKeyValidation, useLegacyName, keyDecipherModeOverride, random, cipherProvider, keyAgreementProvider,
      keyFactoryProvider, macProvider, messageDigestProvider, signatureProvider
    )(verificationKey)(decryptionKey).map(_.flatMap(_.decodeString(charset).asError))

  def getPayloadBytes[F[_]:Async: Compression](skipSignatureVerification: Boolean = false,
                                               skipVerificationKeyResolutionOnNone: Boolean = false,
                                               knownCriticalHeaders: List[String] = List.empty[String],
                                               doKeyValidation: Boolean = true,
                                               useLegacyName: Boolean = false,
                                               keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                                               random: Option[SecureRandom] = None,
                                               cipherProvider: Option[Provider | JProvider] = None,
                                               keyAgreementProvider: Option[Provider | JProvider] = None,
                                               keyFactoryProvider: Option[Provider | JProvider] = None,
                                               macProvider: Option[Provider | JProvider] = None,
                                               messageDigestProvider: Option[Provider | JProvider] = None,
                                               signatureProvider: Option[Provider | JProvider] = None)
                                              (verificationKey: JsonWebSignature => F[Either[Error, Option[Key]]])
                                              (decryptionKey: JsonWebEncryption => F[Either[Error, Key]])
  : F[Either[Error, ByteVector]] =
    val eitherT =
      self match
        case jwe: JsonWebEncryption =>
          for
            key <- EitherT(decryptionKey(jwe))
            payload <- EitherT(jwe.decrypt[F](key, knownCriticalHeaders, doKeyValidation, keyDecipherModeOverride,
              random, cipherProvider, keyAgreementProvider, keyFactoryProvider, macProvider, messageDigestProvider))
          yield
            payload
        case jws: JsonWebSignature =>
          if skipSignatureVerification then jws.decodePayload.eLiftET[F]
          else
            for
              header <- jws.getUnprotectedHeader.eLiftET[F]
              noneAlg = header.algorithm.contains(none)
              key <-
                if noneAlg && skipVerificationKeyResolutionOnNone then None.rLiftET[F, Error]
                else EitherT(verificationKey(jws))
              _ <- EitherT(jws.check[F](key, knownCriticalHeaders, doKeyValidation, useLegacyName, signatureProvider))
              payload <- jws.decodePayload.eLiftET[F]
            yield
              payload
        case _ => UnsupportedJsonWebStructure(self).lLiftET[F, ByteVector]
    eitherT.value
}
