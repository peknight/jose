package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.jwx.JoseHeader
import com.peknight.scodec.bits.ext.syntax.byteVector.{leftHalf, rightHalf}
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.padding.PKCS5Padding
import com.peknight.security.cipher.{AES, Cipher}
import com.peknight.security.mac.Hmac
import com.peknight.security.provider.Provider
import com.peknight.security.random.SecureRandom
import com.peknight.security.syntax.secureRandom.nextBytesF
import scodec.bits.ByteVector

import java.security.{Provider as JProvider, SecureRandom as JSecureRandom}

trait AESHmacSHA2AlgorithmPlatform { self: AESHmacSHA2Algorithm =>
  private val javaAlgorithm: AES = AES / CBC / PKCS5Padding

  private def initializationVector[F[_]: Sync](ivByteLength: Int, ivOverride: Option[ByteVector],
                                               random: Option[JSecureRandom]): F[ByteVector] =
    ivOverride.fold(random.fold(SecureRandom[F])(_.pure[F]).flatMap(_.nextBytesF[F](ivByteLength)))(_.pure[F])


  private def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, iv: ByteVector,
                                  random: Option[JSecureRandom] = None,
                                  cipherProvider: Option[Provider | JProvider] = None,
                                  macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector)] =
    for
      cipherText <- Cipher.rawKeyEncrypt[F](javaAlgorithm, key.rightHalf, input, Some(iv), random, cipherProvider)
      aadLengthBytes = ByteVector.fromLong(aad.length * 8)
      authenticationTagInput = aad ++ iv ++ cipherText ++ aadLengthBytes
      authenticationTag <- self.mac.mac[F](Hmac.secretKeySpec(key.leftHalf), authenticationTagInput, None, macProvider)
    yield
      (cipherText, authenticationTag.take(self.tagTruncationLength))
}
