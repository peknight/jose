package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait RSA1_5Companion extends RSAESAlgorithmPlatform { self: RSAESAlgorithm =>
  override def decryptKey[F[_] : Sync](managementKey: Key, encryptedKey: ByteVector,
                                       cekLength: Int,
                                       cekAlgorithm: SecretKeySpecAlgorithm,
                                       keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                                       random: Option[SecureRandom] = None,
                                       provider: Option[Provider | JProvider] = None): F[Key] =
    for
      cekBytes <- getBytesOrRandom[F](cekLength.asLeft, random)
      randomKey = cekAlgorithm.secretKeySpec(cekBytes)
      unwrappedKeyEither <- super.decryptKey[F](managementKey, encryptedKey, cekLength, cekAlgorithm,
        keyDecipherModeOverride, random, provider).asError
    yield
      unwrappedKeyEither match
        case Right(unwrappedKey) if unwrappedKey.getEncoded.length == cekLength => unwrappedKey
        case _ => randomKey
}
