package com.peknight.jose.jwa.encryption

import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.error.CanNotHaveKey
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.Key

trait DirectEncryptionAlgorithmPlatform { self: DirectEncryptionAlgorithm =>
  def encryptKey(managementKey: Key, cekOverride: Option[ByteVector]): Either[Error, (ByteVector, ByteVector)] =
    cekOverride match
      case Some(_) => CanNotHaveKey(self).asLeft
      case None => (ByteVector(managementKey.getEncoded), ByteVector.empty).asRight

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
