package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.scodec.bits.ext.syntax.byteVector.{leftHalf, rightHalf}
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.padding.PKCS5Padding
import com.peknight.security.cipher.{AES, Cipher}
import com.peknight.security.error.IntegrityError
import com.peknight.security.mac.Hmac
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.{Provider as JProvider, SecureRandom}

trait AESHmacSHA2AlgorithmPlatform { self: AESHmacSHA2Algorithm =>
  private val javaAlgorithm: AES = AES / CBC / PKCS5Padding
  private val ivByteLength: Int = 16

  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[SecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector, ByteVector)] =
    for
      iv <- getBytesOrRandom[F](ivByteLength, ivOverride, random)
      ciphertext <- Cipher.rawKeyEncrypt[F](javaAlgorithm, key.rightHalf, input, Some(iv), provider = cipherProvider)
      authenticationTag <- self.mac.mac[F](Hmac.secretKeySpec(key.leftHalf), authenticationTagInput(ciphertext, aad, iv),
        None, macProvider).map(_.take(self.tagTruncationLength))
    yield
      (iv, ciphertext, authenticationTag)

  private def authenticationTagInput(ciphertext: ByteVector, aad: ByteVector, iv: ByteVector): ByteVector =
    aad ++ iv ++ ciphertext ++ additionalAuthenticatedDataLengthBytes(aad)

  private def additionalAuthenticatedDataLengthBytes(aad: ByteVector): ByteVector =
    ByteVector.fromLong(aad.length * 8)

  def decrypt[F[_]: Sync](key: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector, aad: ByteVector,
                          iv: ByteVector, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]] =
    val eitherT =
      for
        _ <- EitherT(self.mac.mac[F](Hmac.secretKeySpec(key.leftHalf), authenticationTagInput(ciphertext, aad, iv),
            provider = macProvider)
          .map(_.take(self.tagTruncationLength) === authenticationTag)
          .attempt.map(_.asError.flatMap(isTrue(_, IntegrityError))))
        decrypted <- EitherT(Cipher.rawKeyDecrypt[F](javaAlgorithm, key.rightHalf, ciphertext, Some(iv),
            provider = cipherProvider)
          .attempt.map(_.asError))
      yield decrypted
    eitherT.value

  def isAvailable[F[_]: Sync]: F[Boolean] = javaAlgorithm.getMaxAllowedKeyLength[F].map(self.keyByteLength / 2 <= _)
}
