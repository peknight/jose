package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.JoseError
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.security.cipher.AES
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait `ECDH-ESWithAESWrapAlgorithmPlatform` { self: `ECDH-ESWithAESWrapAlgorithm` =>
  def encryptKey[F[_]: Sync](key: Key,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             cekOverride: Option[ByteVector] = None,
                             encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, ContentEncryptionKeys]] =
    val eitherT =
      for
        ContentEncryptionKeys(agreedKey, _, ephemeralPublicKey, _, _, _, _) <- EitherT(`ECDH-ES`.encryptKey[F](
          key, self.encryption.blockSize, AES, None, encryptionAlgorithm, agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, pbes2SaltInput, pbes2Count, random, cipherProvider,
          keyAgreementProvider, keyPairGeneratorProvider, macProvider, messageDigestProvider))
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, _, _, _, _, _) <- EitherT(self.encryption.encryptKey[F](
          AES.secretKeySpec(agreedKey), cekLength, cekAlgorithm, cekOverride, encryptionAlgorithm, agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, pbes2SaltInput, pbes2Count, random, cipherProvider,
          keyAgreementProvider, keyPairGeneratorProvider, macProvider, messageDigestProvider))
      yield
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, ephemeralPublicKey)
    eitherT.value

  def decryptKey[F[_]: Sync](key: Key,
                             encryptedKey: ByteVector,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                             encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                             ephemeralPublicKey: Option[PublicKey] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             authenticationTag: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, Key]] =
    val eitherT =
      for
        agreedKey <- EitherT(`ECDH-ES`.decryptKey[F](key, ByteVector.empty, self.encryption.blockSize, AES,
          keyDecipherModeOverride, encryptionAlgorithm, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo,
          initializationVector, authenticationTag, pbes2SaltInput, pbes2Count, random, cipherProvider,
          keyAgreementProvider, macProvider, messageDigestProvider))
        cek <- EitherT(self.encryption.decryptKey[F](agreedKey, encryptedKey, cekLength, cekAlgorithm,
          keyDecipherModeOverride, encryptionAlgorithm, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo,
          initializationVector, authenticationTag, pbes2SaltInput, pbes2Count, random, cipherProvider,
          keyAgreementProvider, macProvider, messageDigestProvider))
      yield cek
    eitherT.value


  def validateEncryptionKey(key: Key, cekLength: Int): Either[JoseError, Unit] =
    `ECDH-ES`.validateEncryptionKey(key, cekLength)

  def validateDecryptionKey(key: Key, cekLength: Int): Either[JoseError, Unit] =
    `ECDH-ES`.validateDecryptionKey(key, cekLength)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    `ECDH-ES`.isAvailable[F].flatMap {
      case true => self.encryption.isAvailable[F]
      case false => false.pure[F]
    }
}
