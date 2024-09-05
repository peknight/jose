package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.security.cipher.AESWrap
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait AESWrapAlgorithmPlatform { self: AESWrapAlgorithm =>
  def encryptKey[F[_]: Sync](managementKey: Key, cekLengthOrBytes: Either[Int, ByteVector],
                             random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[ByteVector] =
    for
      cek <- getBytesOrRandom[F](cekLengthOrBytes, random)
    yield cek

  def validateKey(managementKey: Key): Either[Error, Unit] = validateAESWrappingKey(managementKey, self, self.blockSize)
  def isAvailable[F[_]: Sync]: F[Boolean] =
    AESWrap.getMaxAllowedKeyLength[F].map(self.blockSize <= _).attempt.map(_.getOrElse(false))
}
