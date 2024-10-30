package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import com.peknight.error.Error
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait KeyManagementAlgorithmPlatform:
  def encryptKey[F[+_]: Sync](managementKey: Key,
                              cekLengthOrBytes: Either[Int, ByteVector],
                              cekAlgorithm: Option[SecretKeySpecAlgorithm] = None,
                              encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
                              agreementPartyUInfo: Option[ByteVector] = None,
                              agreementPartyVInfo: Option[ByteVector] = None,
                              ivOverride: Option[ByteVector] = None,
                              pbes2SaltInput: Option[ByteVector] = None,
                              pbes2Count: Option[Long] = None,
                              random: Option[SecureRandom] = None,
                              cipherProvider: Option[Provider | JProvider] = None,
                              keyAgreementProvider: Option[Provider | JProvider] = None,
                              keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                              macProvider: Option[Provider | JProvider] = None,
                              messageDigestProvider: Option[Provider | JProvider] = None
                             ): F[Either[Error, ContentEncryptionKeys]]

  def decryptKey[F[+_]: Sync](managementKey: Key,
                              cekLength: Option[Int] = None,
                              cekAlgorithm: Option[SecretKeySpecAlgorithm],
                              encryptedKey: Option[ByteVector] = None,
                              ephemeralPublicKey: Option[PublicKey] = None,
                              keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                              encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
                              agreementPartyUInfo: Option[ByteVector] = None,
                              agreementPartyVInfo: Option[ByteVector] = None,
                              iv: Option[ByteVector] = None,
                              authenticationTag: Option[ByteVector] = None,
                              pbes2SaltInput: Option[ByteVector] = None,
                              pbes2Count: Option[Long] = None,
                              random: Option[SecureRandom] = None,
                              cipherProvider: Option[Provider | JProvider] = None,
                              keyAgreementProvider: Option[Provider | JProvider] = None,
                              macProvider: Option[Provider | JProvider] = None,
                              messageDigestProvider: Option[Provider | JProvider] = None
                             ): F[Either[Error, Key]]

  def validateEncryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit]

  def validateDecryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit]
end KeyManagementAlgorithmPlatform
