package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import com.peknight.error.Error
import com.peknight.jose.jwe.ContentEncryptionParts
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{SecureRandom, Provider as JProvider}

trait EncryptionAlgorithmPlatform {

  def encrypt[F[_]: Sync](key: ByteVector, input: ByteVector, aad: ByteVector, ivOverride: Option[ByteVector] = None,
                          random: Option[SecureRandom] = None, cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[ContentEncryptionParts]

  def decrypt[F[_]: Sync](key: ByteVector, initializationVector: ByteVector, ciphertext: ByteVector,
                          authenticationTag: ByteVector, additionalAuthenticatedData: ByteVector,
                          cipherProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]]
}
