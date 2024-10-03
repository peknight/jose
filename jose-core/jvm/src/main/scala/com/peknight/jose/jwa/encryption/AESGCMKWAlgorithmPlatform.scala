package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.security.provider.Provider
import com.peknight.security.spec.{GCMParameterSpec, SecretKeySpecAlgorithm}
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait AESGCMKWAlgorithmPlatform { self: AESGCMKWAlgorithm =>
  def encryptKey[F[_]: Sync](managementKey: Key, cekLengthOrBytes: Either[Int, ByteVector],
                             ivOverride: Option[ByteVector] = None, random: Option[SecureRandom] = None,
                             provider: Option[Provider | JProvider] = None)
  : F[(ByteVector, ByteVector, ByteVector, ByteVector)] =
    for
      contentEncryptionKey <- getBytesOrRandom[F](cekLengthOrBytes, random)
      iv <- getBytesOrRandom[F](ivOverride.toRight(self.ivByteLength), random)
      encrypted <- self.keyEncrypt[F](managementKey, contentEncryptionKey, Some(GCMParameterSpec(self.tagByteLength * 8, iv)),
        provider = provider)
    yield
      val (encryptedKey, authenticationTag) = encrypted.splitAt(encrypted.length - self.tagByteLength)
      (contentEncryptionKey, iv, encryptedKey, authenticationTag)

  def decryptKey[F[_]: Sync](managementKey: Key, encryptedKey: ByteVector,
                             cekAlgorithm: SecretKeySpecAlgorithm, iv: ByteVector,
                             authenticationTag: ByteVector, provider: Option[Provider | JProvider] = None): F[Key] =
    self.keyDecrypt[F](managementKey, encryptedKey ++ authenticationTag,
        Some(GCMParameterSpec(self.tagByteLength * 8, iv)), provider = provider)
      .map(cekAlgorithm.secretKeySpec)

  def validateKey(managementKey: Key): Either[Error, Unit] = validateAESWrappingKey(managementKey, self, self.blockSize)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    isAESGCMKeyAvailable[F](self, self.blockSize, self.ivByteLength, self.tagByteLength)
}
