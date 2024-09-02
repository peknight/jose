package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.padding.PKCS5Padding
import com.peknight.security.random.SecureRandom
import com.peknight.security.syntax.secureRandom.nextBytesF
import scodec.bits.ByteVector

import java.security.SecureRandom as JSecureRandom

trait AESHmacSHA2AlgorithmPlatform { self: AESHmacSHA2Algorithm =>
  private val javaAlgorithm: AES = AES / CBC / PKCS5Padding

  private def initializationVector[F[_]: Sync](ivByteLength: Int, ivOverride: Option[ByteVector],
                                               random: Option[JSecureRandom]): F[ByteVector] =
    ivOverride.fold(random.fold(SecureRandom[F])(_.pure[F]).flatMap(_.nextBytesF[F](ivByteLength)))(_.pure[F])


  private def encrypt[F[_]: Sync](plaintext: ByteVector, aad: ByteVector, key: ByteVector, iv: ByteVector,
                                  headers: JoseHeader): F[ByteVector] =
    ???
}
