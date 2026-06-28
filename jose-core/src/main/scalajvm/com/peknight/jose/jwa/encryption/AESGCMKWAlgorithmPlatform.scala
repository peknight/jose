package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.security.provider.Provider
import com.peknight.security.spec.{GCMParameterSpec, SecretKeySpecAlgorithm}
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait AESGCMKWAlgorithmPlatform { self: AESGCMKWAlgorithm =>
  def encryptKey[F[_]: Sync](key: Key,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             cekOverride: Option[ByteVector] = None,
                             encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
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
    val run =
      for
        contentEncryptionKey <- getBytesOrRandom[F](cekOverride.toRight(cekLength), random)
        iv <- getBytesOrRandom[F](initializationVector.toRight(self.ivByteLength), random)
        encrypted <- self.keyEncrypt[F](key, contentEncryptionKey,
          Some(GCMParameterSpec(self.tagByteLength * 8, iv)), provider = cipherProvider)
      yield
        val (encryptedKey, authenticationTag) = encrypted.splitAt(encrypted.length - self.tagByteLength)
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, initializationVector = Some(iv),
          authenticationTag = Some(authenticationTag))
    run.asError

  def decryptKey[F[_]: Sync](key: Key,
                             encryptedKey: ByteVector,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                             encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
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
    self.keyDecrypt[F](key, encryptedKey ++ authenticationTag.getOrElse(ByteVector.empty),
        Some(GCMParameterSpec(self.tagByteLength * 8, initializationVector.getOrElse(ByteVector.empty))),
        provider = cipherProvider)
      .map(cekAlgorithm.secretKeySpec)
      .asError

  def validateEncryptionKey(key: Key, cekLength: Int): Either[Error, Unit] =
    validateKey(key)

  def validateDecryptionKey(key: Key, cekLength: Int): Either[Error, Unit] =
    validateKey(key)

  def validateKey(key: Key): Either[Error, Unit] = validateAESWrappingKey(key, self, self.blockSize)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    isAESGCMKeyAvailable[F](self, self.blockSize, self.ivByteLength, self.tagByteLength)
}
