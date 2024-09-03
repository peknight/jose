package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import com.peknight.error.Error
import com.peknight.security.provider.Provider
import com.peknight.security.random.SecureRandom
import com.peknight.security.syntax.secureRandom.nextBytesF
import scodec.bits.ByteVector

import java.security.{Provider as JProvider, SecureRandom as JSecureRandom}

trait JWEEncryptionAlgorithmPlatform {

  private[encryption] def initializationVector[F[_]: Sync](ivByteLength: Int, ivOverride: Option[ByteVector] = None,
                                                           random: Option[JSecureRandom] = None): F[ByteVector] =
    ivOverride.fold(random.fold(SecureRandom[F])(_.pure[F]).flatMap(_.nextBytesF[F](ivByteLength)))(_.pure[F])

  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[JSecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector, ByteVector)]

  def decrypt[F[_]: Sync](key: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector, aad: ByteVector,
                          iv: ByteVector, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]]

  def isAvailable[F[_]: Sync]: F[Boolean]
}
