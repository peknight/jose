package com.peknight.jose.jwa

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.applicativeError.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.label
import com.peknight.jose.error.{InvalidKeyAlgorithm, InvalidKeyLength}
import com.peknight.security.cipher.AES
import com.peknight.security.random.SecureRandom
import com.peknight.security.spec.GCMParameterSpec
import com.peknight.security.syntax.secureRandom.nextBytesF
import com.peknight.validation.option.either.nonEmpty
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom as JSecureRandom}

package object encryption:
  private[encryption] def getBytesOrRandom[F[_]: Sync](byteLength: Int, bytesOverride: Option[ByteVector] = None,
                                                       random: Option[JSecureRandom] = None): F[ByteVector] =
    bytesOverride.fold(random.fold(SecureRandom[F])(_.pure[F]).flatMap(_.nextBytesF[F](byteLength)))(_.pure[F])

  private[encryption] def validateAESWrappingKey(managementKey: Key, identifier: AlgorithmIdentifier, keyByteLength: Int)
  : Either[Error, Unit] =
    for
      key <- nonEmpty(Option(managementKey)).label("managementKey")
      _ <- isTrue(AES.algorithm == key.getAlgorithm, InvalidKeyAlgorithm(key.getAlgorithm))
      _ <- Option(key.getEncoded).map(_.length).fold(().asRight)(managementKeyByteLength =>
        isTrue(managementKeyByteLength == keyByteLength, InvalidKeyLength(identifier.identifier, keyByteLength * 8,
          managementKeyByteLength * 8))
      )
    yield
      ()

  private[encryption] def isAESGCMKeyAvailable[F[_]: Sync](algorithm: AES, keyByteLength: Int, ivByteLength: Int,
                                                           tagByteLength: Int): F[Boolean] =
    algorithm.getMaxAllowedKeyLength[F].flatMap { maxAllowedKeyLength =>
    if keyByteLength <= maxAllowedKeyLength then
      val plain = ByteVector(112, 108, 97, 105, 110, 116, 101, 120, 116)
      val aad = ByteVector(97, 97, 100)
      for
        random <- SecureRandom[F]
        cek <- random.nextBytesF[F](keyByteLength)
        iv <- random.nextBytesF[F](ivByteLength)
        _ <- algorithm.keyEncrypt[F](algorithm.secretKeySpec(cek), plain, Some(GCMParameterSpec(tagByteLength * 8, iv)),
          Some(aad))
      yield
        true
    else false.pure[F]
  }.attempt.map(_.getOrElse(false))
end encryption
