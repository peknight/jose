package com.peknight.jose.jwa

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.applicativeError.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.label
import com.peknight.jose.error.{CanNotHaveKey, InvalidKeyAlgorithm, InvalidKeyLength}
import com.peknight.security.Security
import com.peknight.security.cipher.AES
import com.peknight.security.key.factory.{KeyFactory, KeyFactoryAlgorithm}
import com.peknight.security.key.pair.{KeyPairGenerator, KeyPairGeneratorAlgorithm}
import com.peknight.security.random.SecureRandom
import com.peknight.security.spec.GCMParameterSpec
import com.peknight.security.syntax.secureRandom.nextBytesF
import com.peknight.validation.option.either.nonEmpty
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom as JSecureRandom}

package object encryption:
  private[encryption] def randomBytes[F[_]: Sync](length: Int, random: Option[JSecureRandom] = None): F[ByteVector] =
    random.fold(SecureRandom[F])(_.pure[F]).flatMap(_.nextBytesF[F](length))

  private[encryption] def getBytesOrRandom[F[_]: Sync](lengthOrBytes: Either[Int, ByteVector],
                                                       random: Option[JSecureRandom] = None): F[ByteVector] =
    lengthOrBytes.fold(length => randomBytes[F](length, random), _.pure[F])

  private[encryption] def validateAESWrappingKey(managementKey: Key, identifier: AlgorithmIdentifier, keyByteLength: Int)
  : Either[Error, Unit] =
    for
      key <- nonEmptyManagementKey(managementKey)
      _ <- isTrue(AES.algorithm == key.getAlgorithm, InvalidKeyAlgorithm(key.getAlgorithm))
      _ <- validateManagementKeyLength(key, identifier, keyByteLength)
    yield
      ()

  private[encryption] def nonEmptyManagementKey(managementKey: Key): Either[Error, Key] =
    nonEmpty(Option(managementKey)).label("managementKey")

  private[encryption] def validateManagementKeyLength(managementKey: Key, identifier: AlgorithmIdentifier,
                                                      keyByteLength: Int): Either[Error, Unit] =
    Option(managementKey.getEncoded).map(_.length) match
      case Some(managementKeyByteLength) =>
        isTrue(
          managementKeyByteLength == keyByteLength,
          InvalidKeyLength(identifier.identifier, keyByteLength * 8, managementKeyByteLength * 8)
        )
      case None => ().asRight

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

  private[encryption] def isKeyPairAlgorithmAvailable[F[_]: Sync](algorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm)
  : F[Boolean] =
    Security.isAvailable[F](KeyFactory, algorithm).flatMap {
      case true => Security.isAvailable[F](KeyPairGenerator, algorithm)
      case false => false.pure[F]
    }

  private[encryption] def canNotHaveKey(keyOverride: Option[ByteVector], identifier: AlgorithmIdentifier)
  : Either[Error, Unit] =
    keyOverride.fold(().asRight)(_ => CanNotHaveKey(identifier).asLeft)

  private[encryption] def canNotHaveKey(keyLengthOrBytes: Either[Int, ByteVector], identifier: AlgorithmIdentifier)
  : Either[Error, Int] =
    keyLengthOrBytes.fold(_.asRight, _ => CanNotHaveKey(identifier).asLeft)
end encryption
