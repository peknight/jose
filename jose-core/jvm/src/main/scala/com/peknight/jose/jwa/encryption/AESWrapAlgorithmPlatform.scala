package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.jwa.encryption.KeyDecipherMode.Decrypt
import com.peknight.security.cipher.AESWrap
import com.peknight.security.cipher.WrappedKeyType.SecretKey
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait AESWrapAlgorithmPlatform extends KeyWrapAlgorithmPlatform  { self: AESWrapAlgorithm =>

  def validateEncryptionKey(key: Key, cekLength: Int): Either[Error, Unit] =
    validateKey(key)

  def validateDecryptionKey(key: Key, cekLength: Int): Either[Error, Unit] =
    validateKey(key)

  def validateKey(key: Key): Either[Error, Unit] = validateAESWrappingKey(key, self, self.blockSize)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    AESWrap.getMaxAllowedKeyLength[F].map(self.blockSize <= _).attempt.map(_.getOrElse(false))
}
