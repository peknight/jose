package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.error.CanNotHaveKey
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait DirectEncryptionAlgorithmPlatform { self: DirectEncryptionAlgorithm =>
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
    canNotHaveKey(cekOverride, self)
      .as(ContentEncryptionKeys(ByteVector(managementKey.getEncoded), ByteVector.empty))
      .pure[F]

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
    isTrue(encryptedKey.isEmpty, CanNotHaveKey(self)).as(managementKey).pure[F]

  def validateEncryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit] =
    validateKey(managementKey, cekLength)

  def validateDecryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit] =
    validateKey(managementKey, cekLength)

  def validateKey(managementKey: Key, cekLength: Int): Either[Error, Unit] =
    for
      key <- nonEmptyManagementKey(managementKey)
      _ <- validateManagementKeyLength(key, self, cekLength)
    yield
      ()

  def isAvailable[F[_]: Sync]: F[Boolean] = true.pure[F]
}
