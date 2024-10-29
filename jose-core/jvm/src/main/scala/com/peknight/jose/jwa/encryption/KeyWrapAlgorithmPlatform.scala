package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.applicativeError.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.jose.jwa.encryption.KeyDecipherMode.Decrypt
import com.peknight.security.cipher.CipherAlgorithm
import com.peknight.security.cipher.WrappedKeyType.SecretKey
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait KeyWrapAlgorithmPlatform { self: CipherAlgorithm =>

  def encryptKey[F[_]: Sync](managementKey: Key, cekLengthOrBytes: Either[Int, ByteVector],
                             cekAlgorithm: SecretKeySpecAlgorithm, random: Option[SecureRandom] = None,
                             provider: Option[Provider | JProvider] = None): F[(ByteVector, ByteVector)] =
    for
      contentEncryptionKey <- getBytesOrRandom[F](cekLengthOrBytes, random)
      encryptedKey <- self.keyWrap[F](managementKey, cekAlgorithm.secretKeySpec(contentEncryptionKey),
        provider = provider)
    yield (contentEncryptionKey, encryptedKey)

  def decryptKey[F[_]: Sync](managementKey: Key, encryptedKey: ByteVector, cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                             random: Option[SecureRandom] = None,
                             provider: Option[Provider | JProvider] = None): F[Key] =
    keyDecipherModeOverride match
      case Some(Decrypt) =>
        self.keyDecrypt[F](managementKey, encryptedKey, provider = provider).map(cekAlgorithm.secretKeySpec)
      case _ =>
        self.keyUnwrap[F](managementKey, encryptedKey, cekAlgorithm, SecretKey, provider = provider)
}
