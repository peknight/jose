package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import com.peknight.error.Error
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{SecureRandom, Provider as JProvider}

trait JWEEncryptionAlgorithmPlatform {

  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[SecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector, ByteVector)]

  def decrypt[F[_]: Sync](key: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector, aad: ByteVector,
                          iv: ByteVector, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]]

  def isAvailable[F[_]: Sync]: F[Boolean]
}
