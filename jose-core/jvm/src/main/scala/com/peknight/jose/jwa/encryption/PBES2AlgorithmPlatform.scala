package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.{label, message}
import com.peknight.jose.error.MissingKey
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.jose.jwx.stringEncodeToBytes
import com.peknight.security.cipher.{AES, BlockCipher}
import com.peknight.security.mac.MACAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.spec.{SecretKeySpec, SecretKeySpecAlgorithm}
import com.peknight.validation.spire.math.interval.either.{atOrAbove, atOrBelow}
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait PBES2AlgorithmPlatform { self: PBES2Algorithm =>
  private val defaultIterationCount: Long = 8192L * 8
  private val defaultSaltByteLength: Int = 12
  private val maxIterationCount: Long = 2499999L
  def encryptKey[F[_]: Sync](managementKey: Key,
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
        (derivedKey, saltInput, iterationCount) <- deriveForEncrypt[F](managementKey, pbes2SaltInput, pbes2Count,
          random, macProvider)
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, _, _, _, _, _) <- EitherT(self.encryption.encryptKey[F](
          derivedKey, cekLength, cekAlgorithm, cekOverride, encryptionAlgorithm, agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, Some(saltInput), Some(iterationCount), random, cipherProvider,
          keyAgreementProvider, keyPairGeneratorProvider, macProvider, messageDigestProvider))
      yield
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, pbes2SaltInput = Some(saltInput),
          pbes2Count = Some(iterationCount))
    eitherT.value

  def decryptKey[F[_]: Sync](managementKey: Key,
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
        pbes2Count <- pbes2Count.toRight(OptionEmpty.label("pbes2Count")).eLiftET
        pbes2SaltInput <- pbes2SaltInput.toRight(OptionEmpty.label("pbes2SlatInput")).eLiftET
        iterationCount <- atOrBelow(pbes2Count, maxIterationCount)
          .message(s"PBES2 iteration count (p2c=$pbes2Count) cannot be more than $maxIterationCount to avoid " +
            s"excessive resource utilization.")
          .eLiftET
        derivedKey <- deriveKey(self, self.encryption, self.prf, AES, managementKey, iterationCount.toInt, pbes2SaltInput,
          macProvider)
        key <- EitherT(self.encryption.decryptKey[F](derivedKey, encryptedKey, cekLength, cekAlgorithm,
          keyDecipherModeOverride, encryptionAlgorithm, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo,
          initializationVector, authenticationTag, Some(pbes2SaltInput), Some(pbes2Count), random, cipherProvider,
          keyAgreementProvider, macProvider, messageDigestProvider))
      yield
        key
    eitherT.value

  private[encryption] def deriveForEncrypt[F[_]: Sync](managementKey: Key, pbes2SaltInput: Option[ByteVector],
                                                       pbes2Count: Option[Long], random: Option[SecureRandom],
                                                       macProvider: Option[Provider | JProvider]
                                                      ): EitherT[F, Error, (Key, ByteVector, Long)] =
    deriveForEncrypt[F](self, self.encryption, self.prf, AES, managementKey, pbes2SaltInput, pbes2Count,
      random, macProvider)

  private def deriveForEncrypt[F[_]: Sync](identifier: AlgorithmIdentifier, cipher: BlockCipher, prf: MACAlgorithm,
                                           cekAlgorithm: SecretKeySpecAlgorithm, managementKey: Key,
                                           pbes2SaltInput: Option[ByteVector], pbes2Count: Option[Long],
                                           random: Option[SecureRandom], macProvider: Option[Provider | JProvider]
                                          ): EitherT[F, Error, (Key, ByteVector, Long)] =
    for
      iterationCount <- atOrAbove(pbes2Count.getOrElse(defaultIterationCount), 1000L).label("iterationCount").eLiftET
      saltInput <- EitherT(getBytesOrRandom[F](pbes2SaltInput.toRight(defaultSaltByteLength), random).asError)
      _ <- atOrAbove(saltInput.length, 8L).label("saltInput").eLiftET
      derivedKey <- deriveKey[F](identifier, cipher, prf, cekAlgorithm, managementKey, iterationCount.toInt, saltInput,
        macProvider)
    yield
      (derivedKey, saltInput, iterationCount)

  private def deriveKey[F[_]: Sync](identifier: AlgorithmIdentifier, cipher: BlockCipher, prf: MACAlgorithm,
                                    cekAlgorithm: SecretKeySpecAlgorithm, managementKey: Key, iterationCount: Int,
                                    saltInput: ByteVector, provider: Option[Provider | JProvider]
                                   ): EitherT[F, Error, Key] =
    for
      identifierBytes <- stringEncodeToBytes(identifier.identifier).eLiftET
      salt = identifierBytes ++ (0 +: saltInput)
      dkLen = cipher.blockSize
      derivedKeyBytes <- PasswordBasedKeyDerivationFunction2.derive[F](prf, ByteVector(managementKey.getEncoded), salt,
        iterationCount, dkLen, provider)
    yield
      SecretKeySpec(derivedKeyBytes, cekAlgorithm)

  def validateEncryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit] = validateKey(managementKey)

  def validateDecryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit] = validateKey(managementKey)

  def validateKey(managementKey: Key): Either[Error, Unit] =
    Option(managementKey).toRight(MissingKey.label("managementKey")).as(())

  def isAvailable[F[_]: Sync]: F[Boolean] = self.encryption.isAvailable[F]
}
