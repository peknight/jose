package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwa.encryption.KeyDecipherMode.Decrypt
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.security.cipher.CipherAlgorithm
import com.peknight.security.cipher.WrappedKeyType.SecretKey
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.spec.AlgorithmParameterSpec
import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}

trait KeyWrapAlgorithmPlatform { self: CipherAlgorithm =>

  def algorithmParameterSpec: Option[AlgorithmParameterSpec] = None

  def encryptKey[F[_]: Sync](key: Key,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             cekOverride: Option[ByteVector] = None,
                             encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, ContentEncryptionKeys]] =
    val run =
      for
        contentEncryptionKey <- getBytesOrRandom[F](cekOverride.toRight(cekLength), random)
        encryptedKey <- self.keyWrap[F](key, cekAlgorithm.secretKeySpec(contentEncryptionKey),
          algorithmParameterSpec, provider = cipherProvider)
      yield ContentEncryptionKeys(contentEncryptionKey, encryptedKey)
    run.asError

  def decryptKey[F[_]: Sync](key: Key,
                             encryptedKey: ByteVector,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                             encryptionAlgorithm: Option[AlgorithmIdentifier] = None,
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
    val run =
      keyDecipherModeOverride match
        case Some(Decrypt) =>
          self.keyDecrypt[F](key, encryptedKey, algorithmParameterSpec, provider = cipherProvider)
            .map(cekAlgorithm.secretKeySpec)
        case _ =>
          self.keyUnwrap[F](key, encryptedKey, cekAlgorithm, SecretKey, algorithmParameterSpec,
            provider = cipherProvider)
    run.asError
}
