package com.peknight.jose.jwe

import cats.data.EitherT
import cats.effect.{Async, Concurrent, Sync}
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.option.*
import cats.{Applicative, Id}
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, rLiftET}
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.InvalidKeyLength
import com.peknight.jose.jwa.compression.CompressionAlgorithm
import com.peknight.jose.jwa.encryption.{EncryptionAlgorithm, KeyManagementAlgorithm}
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jwx.*
import com.peknight.jose.{algorithmLabel, encryptionAlgorithmLabel}
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.{isTrue, typed}
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.StandardCharsets
import java.security.{Key, PublicKey, Provider as JProvider}

trait JsonWebEncryptionCompanion:

  def encryptString[F[_] : Async : Compression](header: JoseHeader, plaintextString: String, key: Key,
                                                sharedHeader: Option[JoseHeader] = None,
                                                recipientHeader: Option[JoseHeader] = None,
                                                additionalAuthenticatedData: Option[ByteVector] = None,
                                                configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryption]] =
    handleEncryptPlaintext[F](header, stringEncodeToBytes(plaintextString, configuration.charset), key, sharedHeader,
      recipientHeader, additionalAuthenticatedData, configuration)

  def encryptJson[F[_], A](header: JoseHeader, plaintextValue: A, key: Key,
                           sharedHeader: Option[JoseHeader] = None,
                           recipientHeader: Option[JoseHeader] = None,
                           additionalAuthenticatedData: Option[ByteVector] = None,
                           configuration: JoseConfiguration = JoseConfiguration.default)
                          (using Async[F], Compression[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebEncryption]] =
    handleEncryptPlaintext[F](header, encodeToJsonBytes(plaintextValue), key, sharedHeader, recipientHeader,
      additionalAuthenticatedData, configuration)

  private def handleEncryptPlaintext[F[_] : Async : Compression](header: JoseHeader,
                                                                 plaintextEither: Either[Error, ByteVector],
                                                                 key: Key,
                                                                 sharedHeader: Option[JoseHeader] = None,
                                                                 recipientHeader: Option[JoseHeader] = None,
                                                                 additionalAuthenticatedData: Option[ByteVector] = None,
                                                                 configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryption]] =
    plaintextEither match
      case Left(error) => error.asLeft[JsonWebEncryption].pure[F]
      case Right(plaintext) => encrypt[F](header, plaintext, key, sharedHeader, recipientHeader,
        additionalAuthenticatedData, configuration)

  def encrypt[F[_]: Async: Compression](header: JoseHeader, plaintext: ByteVector, key: Key,
                                        sharedHeader: Option[JoseHeader] = None,
                                        recipientHeader: Option[JoseHeader] = None,
                                        additionalAuthenticatedData: Option[ByteVector] = None,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryption]] =
    val h = mergedHeader(header, sharedHeader, recipientHeader)
    val eitherT =
      for
        algorithm <- h.algorithm.toRight(OptionEmpty.label(algorithmLabel)).eLiftET[F]
        algorithm <- typed[KeyManagementAlgorithm](algorithm).eLiftET
        encryptionAlgorithm <- h.encryptionAlgorithm.toRight(OptionEmpty.label(encryptionAlgorithmLabel)).eLiftET
        _ <-
          if configuration.doKeyValidation then
            algorithm.validateEncryptionKey(key, encryptionAlgorithm.cekByteLength).eLiftET
          else ().rLiftET
        agreementPartyUInfo <- decodeOption(h.agreementPartyUInfo).eLiftET[F]
        agreementPartyVInfo <- decodeOption(h.agreementPartyVInfo).eLiftET[F]
        initializationVector <- decodeOption(h.initializationVector).eLiftET[F]
        pbes2SaltInput <- decodeOption(h.pbes2SaltInput).eLiftET[F]
        contentEncryptionKeys <- EitherT(algorithm.encryptKey[F](key, encryptionAlgorithm.cekByteLength,
          encryptionAlgorithm.cekAlgorithm, configuration.cekOverride, Some(encryptionAlgorithm), agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, pbes2SaltInput, h.pbes2Count, configuration.random,
          configuration.cipherProvider, configuration.keyAgreementProvider, configuration.keyPairGeneratorProvider,
          configuration.macProvider, configuration.messageDigestProvider))
        contentEncryptionKey = contentEncryptionKeys.contentEncryptionKey
        _ <- checkCek(encryptionAlgorithm, contentEncryptionKey)
        (nextHeader, nextRecipientHeader) =
          if configuration.writeCekHeadersToRecipientHeader then
            (
              header,
              recipientHeader.fold(contentEncryptionKeys.toHeader)(rh => Some(contentEncryptionKeys.updateHeader(rh)))
            )
          else
            (contentEncryptionKeys.updateHeader(header), recipientHeader)
        aad <- additionalAuthenticatedData match
          case Some(bytes) => bytes.rLiftET
          case None =>
            encodeToBase(nextHeader, Base64UrlNoPad)
              .flatMap(protectedHeader => stringEncodeToBytes(protectedHeader.value, StandardCharsets.US_ASCII))
              .eLiftET
        plaintextBytes <- compress[F](h.compressionAlgorithm, plaintext)
        contentEncryptionParts <- EitherT(encryptionAlgorithm.encrypt[F](contentEncryptionKey, plaintextBytes,
          aad, configuration.ivOverride, configuration.random, configuration.cipherProvider, configuration.macProvider
        ).asError)
      yield
        JsonWebEncryption(nextHeader, sharedHeader, nextRecipientHeader,
          Base64UrlNoPad.fromByteVector(contentEncryptionKeys.encryptedKey),
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.initializationVector),
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext),
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag),
          Some(Base64UrlNoPad.fromByteVector(aad))
        )
    eitherT.value

  def handleDecrypt[F[_]: Async: Compression](header: JoseHeader, key: Key, encryptedKey: ByteVector,
                                              initializationVector: ByteVector, ciphertext: ByteVector,
                                              authenticationTag: ByteVector, additionalAuthenticatedData: ByteVector,
                                              configuration: JoseConfiguration = JoseConfiguration.default
                                             ): F[Either[Error, ByteVector]] =
    val eitherT =
      for
        algorithm <- header.algorithm.toRight(OptionEmpty.label(algorithmLabel)).eLiftET[F]
        algorithm <- typed[KeyManagementAlgorithm](algorithm).eLiftET
        encryptionAlgorithm <- header.encryptionAlgorithm.toRight(OptionEmpty.label(encryptionAlgorithmLabel)).eLiftET
        _ <-
          if configuration.doKeyValidation then
            algorithm.validateDecryptionKey(key, encryptionAlgorithm.cekByteLength).eLiftET
          else ().rLiftET
        ephemeralPublicKey <- publicKey[F](header.ephemeralPublicKey, configuration.keyFactoryProvider)
        agreementPartyUInfo <- decodeOption(header.agreementPartyUInfo).eLiftET[F]
        agreementPartyVInfo <- decodeOption(header.agreementPartyVInfo).eLiftET[F]
        initializationVectorH <- decodeOption(header.initializationVector).eLiftET[F]
        authenticationTagH <- decodeOption(header.authenticationTag).eLiftET[F]
        pbes2SaltInput <- decodeOption(header.pbes2SaltInput).eLiftET[F]
        cek <- EitherT(algorithm.decryptKey[F](key, encryptedKey, encryptionAlgorithm.cekByteLength,
          encryptionAlgorithm.cekAlgorithm, configuration.keyDecipherModeOverride, Some(encryptionAlgorithm),
          ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo, initializationVectorH, authenticationTagH,
          pbes2SaltInput, header.pbes2Count, configuration.random, configuration.cipherProvider, configuration.keyAgreementProvider,
          configuration.macProvider, configuration.messageDigestProvider))
        rawCek = ByteVector(cek.getEncoded)
        _ <- checkCek[F](encryptionAlgorithm, rawCek)
        decrypted <- EitherT(encryptionAlgorithm.decrypt[F](rawCek, initializationVector, ciphertext, authenticationTag,
          additionalAuthenticatedData, configuration.cipherProvider, configuration.macProvider))
        res <- decompress[F](header.compressionAlgorithm, decrypted)
      yield
        res
    eitherT.value

  private def checkCek[F[_] : Applicative](encryptionAlgorithm: EncryptionAlgorithm, contentEncryptionKey: ByteVector)
  : EitherT[F, Error, Unit] =
    val expectedLength = encryptionAlgorithm.cekByteLength
    val actualLength = contentEncryptionKey.length
    isTrue(actualLength == expectedLength, InvalidKeyLength(encryptionAlgorithm.identifier, expectedLength * 8,
      actualLength.intValue * 8)).eLiftET

  private def compress[F[_] : Concurrent : Compression](compressionAlgorithm: Option[CompressionAlgorithm],
                                                        plaintextBytes: ByteVector): EitherT[F, Error, ByteVector] =
    compressionAlgorithm match
      case Some(compressionAlgorithm) => EitherT(compressionAlgorithm.compress[F](plaintextBytes).asError)
      case None => plaintextBytes.rLiftET

  private def decompress[F[_] : Concurrent : Compression](compressionAlgorithm: Option[CompressionAlgorithm],
                                                          data: ByteVector): EitherT[F, Error, ByteVector] =
    compressionAlgorithm match
      case Some(compressionAlgorithm) => EitherT(compressionAlgorithm.decompress[F](data))
      case None => data.rLiftET

  private def publicKey[F[_]: Sync](ephemeralPublicKey: Option[JsonWebKey],
                                    keyFactoryProvider: Option[Provider | JProvider] = None
                                   ): EitherT[F, Error, Option[PublicKey]] =
    ephemeralPublicKey match
      case Some(jwk) =>
        for
          jwk <- typed[AsymmetricJsonWebKey](jwk).eLiftET
          publicKey <- EitherT(jwk.toPublicKey[F](keyFactoryProvider))
        yield Some(publicKey)
      case _ => none.rLiftET
end JsonWebEncryptionCompanion
