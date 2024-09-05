package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.security.cipher.AESWrap

import java.security.Key

trait AESWrapAlgorithmPlatform { self: AESWrapAlgorithm =>
  def validateKey(managementKey: Key): Either[Error, Unit] = validateAESWrappingKey(managementKey, self, self.blockSize)
  def isAvailable[F[_]: Sync]: F[Boolean] =
    AESWrap.getMaxAllowedKeyLength[F].map(self.blockSize <= _).attempt.map(_.getOrElse(false))
}
