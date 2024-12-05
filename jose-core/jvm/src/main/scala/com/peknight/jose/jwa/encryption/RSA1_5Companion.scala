package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait RSA1_5Companion extends RSAESAlgorithmPlatform { self: RSAESAlgorithm =>
  override def decryptKey[F[_] : Sync](key: Key,
                                       encryptedKey: ByteVector,
                                       cekLength: Int,
                                       cekAlgorithm: SecretKeySpecAlgorithm,
                                       keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                                       encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                                       ephemeralPublicKey: Option[PublicKey] = None,
                                       agreementPartyUInfo: Option[ByteVector] = None,
                                       agreementPartyVInfo: Option[ByteVector] = None,
                                       initializationVector: Option[ByteVector] = None,
                                       authenticationTag: Option[ByteVector] = None,
                                       pbes2SaltInput: Option[ByteVector] = None,
                                       pbes2Count: Option[Long] = None,
                                       random: Option[SecureRandom] = None,
                                       cipherProvider: Option[Provider | JProvider] = None,
                                       keyAgreementProvider: Option[Provider | JProvider] = None,
                                       macProvider: Option[Provider | JProvider] = None,
                                       messageDigestProvider: Option[Provider | JProvider] = None
                                      ): F[Either[Error, Key]] =
    super.decryptKey[F](key, encryptedKey, cekLength, cekAlgorithm, keyDecipherModeOverride,
      encryptionAlgorithm, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo, initializationVector,
      authenticationTag, pbes2SaltInput, pbes2Count, random, cipherProvider, keyAgreementProvider, macProvider,
      messageDigestProvider)
      .flatMap {
        case Right(unwrappedKey) if unwrappedKey.getEncoded.length == cekLength => unwrappedKey.asRight.pure[F]
        case _ => randomBytes[F](cekLength, random).map(cekAlgorithm.secretKeySpec).asError
      }
}
