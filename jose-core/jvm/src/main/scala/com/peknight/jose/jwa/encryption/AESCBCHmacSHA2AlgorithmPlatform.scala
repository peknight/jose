package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.scodec.bits.ext.syntax.byteVector.{leftHalf, rightHalf}
import com.peknight.security.cipher.{AES, Cipher}
import com.peknight.security.error.IntegrityError
import com.peknight.security.mac.Hmac
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.{SecureRandom, Provider as JProvider}

trait AESCBCHmacSHA2AlgorithmPlatform { self: AESCBCHmacSHA2Algorithm =>
  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[SecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector, ByteVector)] =
    for
      iv <- getBytesOrRandom[F](ivOverride.toRight(self.ivByteLength), random)
      ciphertext <- Cipher.rawKeyEncrypt[F](self.javaAlgorithm, key.rightHalf, input, Some(iv), provider = cipherProvider)
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
        macBytes <- EitherT(self.mac.mac[F](Hmac.secretKeySpec(key.leftHalf),
          authenticationTagInput(ciphertext, aad, iv), provider = macProvider).asError)
        _ <- isTrue(macBytes.take(self.tagTruncationLength) === authenticationTag, IntegrityError).eLiftET
        decrypted <- EitherT(Cipher.rawKeyDecrypt[F](self.javaAlgorithm, key.rightHalf, ciphertext, Some(iv),
            provider = cipherProvider).asError)
      yield decrypted
    eitherT.value

  def isAvailable[F[_]: Sync]: F[Boolean] =
    self.javaAlgorithm.getMaxAllowedKeyLength[F].map(self.keyByteLength / 2 <= _).attempt.map(_.getOrElse(false))
}
