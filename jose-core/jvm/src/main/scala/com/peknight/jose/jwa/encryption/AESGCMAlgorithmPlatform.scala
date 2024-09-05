package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.padding.NoPadding
import com.peknight.security.provider.Provider
import com.peknight.security.random.SecureRandom
import com.peknight.security.spec.GCMParameterSpec
import com.peknight.security.syntax.secureRandom.nextBytesF
import scodec.bits.ByteVector

import java.security.{Provider as JProvider, SecureRandom as JSecureRandom}

trait AESGCMAlgorithmPlatform { self: AESGCMAlgorithm =>
  private val javaAlgorithm: AES = AES / GCM / NoPadding
  private val ivByteLength: Int = 12
  private val tagByteLength: Int = 16

  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[JSecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector, ByteVector)] =
    for
      iv <- getBytesOrRandom[F](ivByteLength, ivOverride, random)
      encrypted <- javaAlgorithm.keyEncrypt[F](javaAlgorithm.secretKeySpec(key), input,
        Some(GCMParameterSpec(tagByteLength * 8, iv)), Some(aad), provider = cipherProvider)
    yield
      val (ciphertext, authenticationTag) = encrypted.splitAt(encrypted.length - tagByteLength)
      (iv, ciphertext, authenticationTag)

  def decrypt[F[_]: Sync](key: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector, aad: ByteVector,
                          iv: ByteVector, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]] =
    javaAlgorithm.keyDecrypt[F](javaAlgorithm.secretKeySpec(key), ciphertext ++ authenticationTag,
      Some(GCMParameterSpec(tagByteLength * 8, iv)), Some(aad), provider = cipherProvider).attempt.map(_.asError)

  def isAvailable[F[_]: Sync]: F[Boolean] = javaAlgorithm.getMaxAllowedKeyLength[F].flatMap { maxAllowedKeyLength =>
    if self.blockSize <= maxAllowedKeyLength then
      val plain = ByteVector(112, 108, 97, 105, 110, 116, 101, 120, 116)
      val aad = ByteVector(97, 97, 100)
      for
        random <- SecureRandom[F]
        cek <- random.nextBytesF[F](self.blockSize)
        iv <- random.nextBytesF[F](ivByteLength)
        _ <- javaAlgorithm.keyEncrypt[F](javaAlgorithm.secretKeySpec(cek), plain,
          Some(GCMParameterSpec(tagByteLength * 8, iv)), Some(aad))
      yield
        true
    else false.pure[F]
  }.attempt.map(_.getOrElse(false))
}
