package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.security.provider.Provider
import com.peknight.security.spec.GCMParameterSpec
import scodec.bits.ByteVector

import java.security.{Provider as JProvider, SecureRandom as JSecureRandom}

trait AESGCMAlgorithmPlatform { self: AESGCMAlgorithm =>
  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[JSecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector, ByteVector)] =
    for
      iv <- getBytesOrRandom[F](ivOverride.toRight(self.ivByteLength), random)
      encrypted <- self.keyEncrypt[F](self.secretKeySpec(key), input,
        Some(GCMParameterSpec(self.tagByteLength * 8, iv)), Some(aad), provider = cipherProvider)
    yield
      val (ciphertext, authenticationTag) = encrypted.splitAt(encrypted.length - self.tagByteLength)
      (iv, ciphertext, authenticationTag)

  def decrypt[F[_]: Sync](key: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector, aad: ByteVector,
                          iv: ByteVector, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]] =
    self.keyDecrypt[F](self.secretKeySpec(key), ciphertext ++ authenticationTag,
      Some(GCMParameterSpec(self.tagByteLength * 8, iv)), Some(aad), provider = cipherProvider).attempt.map(_.asError)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    isAESGCMKeyAvailable[F](self, self.blockSize, self.ivByteLength, self.tagByteLength)
}
