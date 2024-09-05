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
  def encryptKey[F[_]: Sync](managementKey: Key, keyByteLength: Int, cekOverride: Option[ByteVector] = None,
                             ivOverride: Option[ByteVector] = None, random: Option[SecureRandom] = None,
                             provider: Option[Provider | JProvider] = None)
  : F[(ByteVector, ByteVector, ByteVector, ByteVector)] =
    for
      cek <- getBytesOrRandom[F](keyByteLength, cekOverride, random)
      iv <- getBytesOrRandom[F](self.ivByteLength, ivOverride, random)
      encrypted <- self.keyEncrypt[F](managementKey, cek, Some(GCMParameterSpec(self.tagByteLength * 8, iv)),
        provider = provider)
    yield
      val (encryptedKey, authenticationTag) = encrypted.splitAt(encrypted.length - self.tagByteLength)
      (cek, iv, encryptedKey, authenticationTag)

  def decryptKey[F[_]: Sync](managementKey: Key, algorithm: SecretKeySpecAlgorithm, iv: ByteVector,
                             encryptedKey: ByteVector, authenticationTag: ByteVector,
                             provider: Option[Provider | JProvider] = None): F[Key] =
    self.keyDecrypt[F](managementKey, encryptedKey ++ authenticationTag,
      Some(GCMParameterSpec(self.tagByteLength * 8, iv)), provider = provider).map(algorithm.secretKeySpec)

  def validateKey(managementKey: Key): Either[Error, Unit] = validateAESWrappingKey(managementKey, self, self.blockSize)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    isAESGCMKeyAvailable[F](self, self.blockSize, self.ivByteLength, self.tagByteLength)
}
