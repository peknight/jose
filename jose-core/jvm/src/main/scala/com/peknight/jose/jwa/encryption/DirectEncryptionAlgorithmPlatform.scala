package com.peknight.jose.jwa.encryption

import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.error.CanNotHaveKey
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.Key

trait DirectEncryptionAlgorithmPlatform { self: DirectEncryptionAlgorithm =>
  def encryptKey(managementKey: Key, cekOverride: Option[ByteVector] = None): Either[Error, (ByteVector, ByteVector)] =
    canNotHaveKey(cekOverride, self).as((ByteVector(managementKey.getEncoded), ByteVector.empty))

  def decryptKey(managementKey: Key, encryptedKey: ByteVector): Either[Error, Key] =
    isTrue(encryptedKey.isEmpty, CanNotHaveKey(self)).as(managementKey)

  def validateKey(managementKey: Key, contentEncryptionKeyByteLength: Int): Either[Error, Unit] =
    for
      key <- nonEmptyManagementKey(managementKey)
      _ <- validateManagementKeyLength(key, self, contentEncryptionKeyByteLength)
    yield
      ()

  def isAvailable: Boolean = true
}
