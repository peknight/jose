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
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.InvalidKeyLength
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

import java.nio.charset.{Charset, StandardCharsets}
import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait JsonWebEncryptionCompanion:
  def encrypt[F[_]: Async: Compression](managementKey: Key, plaintext: ByteVector, header: JoseHeader,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryption]] =
    val eitherT =
      for
        algorithm <- header.algorithm.toRight(OptionEmpty.label(algorithmLabel)).eLiftET[F]
        algorithm <- typed[KeyManagementAlgorithm](algorithm).eLiftET
        encryptionAlgorithm <- header.encryptionAlgorithm.toRight(OptionEmpty.label(encryptionAlgorithmLabel)).eLiftET
        _ <-
          if configuration.doKeyValidation then
            algorithm.validateEncryptionKey(managementKey, encryptionAlgorithm.cekByteLength).eLiftET
          else ().rLiftET
        agreementPartyUInfo <- decodeOption(header.agreementPartyUInfo).eLiftET[F]
        agreementPartyVInfo <- decodeOption(header.agreementPartyVInfo).eLiftET[F]
        initializationVector <- decodeOption(header.initializationVector).eLiftET[F]
        pbes2SaltInput <- decodeOption(header.pbes2SaltInput).eLiftET[F]
        contentEncryptionKeys <- EitherT(algorithm.encryptKey[F](managementKey, encryptionAlgorithm.cekByteLength,
          encryptionAlgorithm.cekAlgorithm, configuration.cekOverride, Some(encryptionAlgorithm), agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, pbes2SaltInput, header.pbes2Count, configuration.random,
          configuration.cipherProvider, configuration.keyAgreementProvider, configuration.keyPairGeneratorProvider,
          configuration.macProvider, configuration.messageDigestProvider))
        contentEncryptionKey = contentEncryptionKeys.contentEncryptionKey
        nextHeader = update(header, contentEncryptionKeys)
        protectedHeader <- encodeToBase(nextHeader, Base64UrlNoPad).eLiftET
        additionalAuthenticatedData <- ByteVector.encodeAscii(protectedHeader.value).asError.eLiftET
        _ <- checkCek(encryptionAlgorithm, contentEncryptionKey)
        plaintextBytes <- compress[F](nextHeader, plaintext)
        contentEncryptionParts <- EitherT(encryptionAlgorithm.encrypt[F](contentEncryptionKey, plaintextBytes,
          additionalAuthenticatedData, configuration.ivOverride, configuration.random, configuration.cipherProvider,
          configuration.macProvider
        ).asError)
      yield
        JsonWebEncryption(nextHeader, None, None,
          Base64UrlNoPad.fromByteVector(contentEncryptionKeys.encryptedKey),
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.initializationVector),
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext),
          Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag),
          Some(Base64UrlNoPad.fromByteVector(additionalAuthenticatedData))
        )
    eitherT.value

  def encryptString[F[_]: Async : Compression](managementKey: Key, plaintextString: String, header: JoseHeader,
                                               configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryption]] =
    doHandleEncrypt[F](managementKey, stringEncodeToBytes(plaintextString, configuration.charset), header, configuration)

  def encryptJson[F[_], A](managementKey: Key, plaintextValue: A, header: JoseHeader,
                           configuration: JoseConfiguration = JoseConfiguration.default)
                          (using Async[F], Compression[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebEncryption]] =
    doHandleEncrypt[F](managementKey, encodeToJsonBytes(plaintextValue), header, configuration)
      
  private def doHandleEncrypt[F[_]: Async: Compression](managementKey: Key, plaintextEither: Either[Error, ByteVector],
                                                        header: JoseHeader, 
                                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryption]] =
    plaintextEither match
      case Left(error) => error.asLeft[JsonWebEncryption].pure[F]
      case Right(plaintext) => encrypt[F](managementKey, plaintext, header, configuration)

  def handleDecrypt[F[_]: Async: Compression](managementKey: Key, encryptedKey: ByteVector,
                                              initializationVector: ByteVector, ciphertext: ByteVector,
                                              authenticationTag: ByteVector,
                                              additionalAuthenticatedData: ByteVector,
                                              header: JoseHeader,
                                              configuration: JoseConfiguration = JoseConfiguration.default
                                             ): F[Either[Error, ByteVector]] =
    val eitherT =
      for
        algorithm <- header.algorithm.toRight(OptionEmpty.label(algorithmLabel)).eLiftET[F]
        algorithm <- typed[KeyManagementAlgorithm](algorithm).eLiftET
        encryptionAlgorithm <- header.encryptionAlgorithm.toRight(OptionEmpty.label(encryptionAlgorithmLabel)).eLiftET
        _ <-
          if configuration.doKeyValidation then
            algorithm.validateDecryptionKey(managementKey, encryptionAlgorithm.cekByteLength).eLiftET
          else ().rLiftET
        ephemeralPublicKey <- publicKey[F](header.ephemeralPublicKey, configuration.keyFactoryProvider)
        agreementPartyUInfo <- decodeOption(header.agreementPartyUInfo).eLiftET[F]
        agreementPartyVInfo <- decodeOption(header.agreementPartyVInfo).eLiftET[F]
        initializationVectorH <- decodeOption(header.initializationVector).eLiftET[F]
        authenticationTagH <- decodeOption(header.authenticationTag).eLiftET[F]
        pbes2SaltInput <- decodeOption(header.pbes2SaltInput).eLiftET[F]
        cek <- EitherT(algorithm.decryptKey[F](managementKey, encryptedKey, encryptionAlgorithm.cekByteLength,
          encryptionAlgorithm.cekAlgorithm, configuration.keyDecipherModeOverride, Some(encryptionAlgorithm),
          ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo, initializationVectorH, authenticationTagH,
          pbes2SaltInput, header.pbes2Count, configuration.random, configuration.cipherProvider, configuration.keyAgreementProvider,
          configuration.macProvider, configuration.messageDigestProvider))
        rawCek = ByteVector(cek.getEncoded)
        _ <- checkCek[F](encryptionAlgorithm, rawCek)
        decrypted <- EitherT(encryptionAlgorithm.decrypt[F](rawCek, initializationVector, ciphertext, authenticationTag,
          additionalAuthenticatedData, configuration.cipherProvider, configuration.macProvider))
        res <- decompress[F](header, decrypted)
      yield
        res
    eitherT.value

  private def checkCek[F[_] : Applicative](encryptionAlgorithm: EncryptionAlgorithm, contentEncryptionKey: ByteVector)
  : EitherT[F, Error, Unit] =
    val expectedLength = encryptionAlgorithm.cekByteLength
    val actualLength = contentEncryptionKey.length
    isTrue(actualLength == expectedLength, InvalidKeyLength(encryptionAlgorithm.identifier, expectedLength * 8,
      actualLength.intValue * 8)).eLiftET

  private def compress[F[_] : Concurrent : Compression](header: JoseHeader, plaintextBytes: ByteVector)
  : EitherT[F, Error, ByteVector] =
    header.compressionAlgorithm match
      case Some(compressionAlgorithm) => EitherT(compressionAlgorithm.compress[F](plaintextBytes).asError)
      case None => plaintextBytes.rLiftET

  private def decompress[F[_] : Concurrent : Compression](header: JoseHeader, data: ByteVector)
  : EitherT[F, Error, ByteVector] =
    header.compressionAlgorithm match
      case Some(compressionAlgorithm) => EitherT(compressionAlgorithm.decompress[F](data))
      case None => data.rLiftET

  private def update(header: JoseHeader, contentEncryptionKeys: ContentEncryptionKeys): JoseHeader =
    header.copy(
      ephemeralPublicKey = contentEncryptionKeys.ephemeralPublicKey.orElse(header.ephemeralPublicKey),
      initializationVector = contentEncryptionKeys.initializationVector.map(Base64UrlNoPad.fromByteVector)
        .orElse(header.initializationVector),
      authenticationTag = contentEncryptionKeys.authenticationTag.map(Base64UrlNoPad.fromByteVector)
        .orElse(header.authenticationTag),
      pbes2SaltInput = contentEncryptionKeys.pbes2SaltInput.map(Base64UrlNoPad.fromByteVector)
        .orElse(header.pbes2SaltInput),
      pbes2Count = contentEncryptionKeys.pbes2Count.orElse(header.pbes2Count)
    )

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
