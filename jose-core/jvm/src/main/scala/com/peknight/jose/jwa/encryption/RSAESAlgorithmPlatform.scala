package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.checkRSAKeySize
import com.peknight.validation.std.either.typed

import java.security.interfaces.RSAKey
import java.security.{Key, PrivateKey, PublicKey}

trait RSAESAlgorithmPlatform extends KeyWrapAlgorithmPlatform { self: RSAESAlgorithm =>
  def validateEncryptionKey(managementKey: Key): Either[Error, Unit] =
    for
      publicKey <- typed[PublicKey](managementKey)
      _ <- publicKey match
        case rsaKey: RSAKey => checkRSAKeySize(rsaKey)
        case _ => ().asRight
    yield ()

  def validateDecryptionKey(managementKey: Key): Either[Error, Unit] =
    for
      privateKey <- typed[PrivateKey](managementKey)
      _ <- privateKey match
        case rsaKey: RSAKey => checkRSAKeySize(rsaKey)
        case _ => ().asRight
    yield ()

  def isAvailable[F[+_]: Sync]: F[Boolean] = self.getCipher[F]().asError.map(_.isRight)
}
