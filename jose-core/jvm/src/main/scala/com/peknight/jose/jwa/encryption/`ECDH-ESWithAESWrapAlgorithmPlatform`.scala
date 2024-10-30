package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.applicative.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.JoseError
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.security.cipher.AES
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait `ECDH-ESWithAESWrapAlgorithmPlatform` { self: `ECDH-ESWithAESWrapAlgorithm` =>
  def encryptKey[F[_]: Sync](managementKey: Key, cekLengthOrBytes: Either[Int, ByteVector],
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             random: Option[SecureRandom] = None,
                             keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None,
                             cipherProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, (ByteVector, ByteVector, PublicKey)]] =
    val eitherT =
      for
        (agreedKey, publicKey) <- EitherT(`ECDH-ES`.encryptKey[F](managementKey, self.encryption.blockSize.asLeft,
          encryptionAlgorithm, agreementPartyUInfo, agreementPartyVInfo, random, keyPairGeneratorProvider,
          keyAgreementProvider, messageDigestProvider))
        (contentEncryptionKey, encryptedKey) <- EitherT(self.encryption.encryptKey[F](AES.secretKeySpec(agreedKey),
          cekLengthOrBytes, cekAlgorithm, random,
          cipherProvider).asError)
      yield (contentEncryptionKey, encryptedKey, publicKey)
    eitherT.value

  def decryptKey[F[+_]: Sync](managementKey: Key, encryptedKey: ByteVector, ephemeralPublicKey: PublicKey,
                              cekLength: Int, cekAlgorithm: SecretKeySpecAlgorithm,
                              encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
                              agreementPartyUInfo: Option[ByteVector] = None,
                              agreementPartyVInfo: Option[ByteVector] = None,
                              keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                              random: Option[SecureRandom] = None,
                              keyAgreementProvider: Option[Provider | JProvider] = None,
                              messageDigestProvider: Option[Provider | JProvider] = None,
                              cipherProvider: Option[Provider | JProvider] = None
                             ): F[Either[Error, Key]] =
    val eitherT =
      for
        agreedKey <- EitherT(`ECDH-ES`.decryptKey[F](managementKey, ephemeralPublicKey, self.encryption.blockSize, AES,
          encryptionAlgorithm, agreementPartyUInfo, agreementPartyVInfo, keyAgreementProvider, messageDigestProvider))
        key <- EitherT(self.encryption.decryptKey[F](agreedKey, encryptedKey, cekLength, cekAlgorithm,
          keyDecipherModeOverride, random, cipherProvider).asError)
      yield key
    eitherT.value


  def validateEncryptionKey(managementKey: Key): Either[JoseError, Unit] =
    `ECDH-ES`.validateEncryptionKey(managementKey)

  def validateDecryptionKey(managementKey: Key): Either[JoseError, Unit] =
    `ECDH-ES`.validateDecryptionKey(managementKey)

  def isAvailable[F[_]: Sync]: F[Boolean] =
    `ECDH-ES`.isAvailable[F].flatMap {
      case true => self.encryption.isAvailable[F]
      case false => false.pure[F]
    }
}
