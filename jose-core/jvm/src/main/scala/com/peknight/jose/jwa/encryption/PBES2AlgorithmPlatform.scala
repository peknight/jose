package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import com.peknight.error.Error
import scodec.bits.ByteVector
import com.peknight.validation.spire.math.interval.either.atOrAbove
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.{asError, label}
import com.peknight.security.provider.Provider

import java.security.{SecureRandom, Provider as JProvider}

trait PBES2AlgorithmPlatform { self: PBES2Algorithm =>
  private val defaultIterationCount: Long = 8192L * 8;
  private val defaultSaltByteLength: Int = 12
  def encryptKey[F[_]: Sync](pbes2SaltInput: Option[ByteVector], pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             macProvider: Option[Provider | JProvider] = None)
  : F[Either[Error, (ByteVector, Long)]] =
    val eitherT =
      for
        iterationCount <- atOrAbove(pbes2Count.getOrElse(defaultIterationCount), 1000L).label("iterationCount").eLiftET
        saltInput <- EitherT(getBytesOrRandom[F](pbes2SaltInput.toRight(defaultSaltByteLength), random).asError)
        _ <- atOrAbove(saltInput.length, 8L).label("saltInput").eLiftET
        identifierBytes <- ByteVector.encodeUtf8(self.identifier).asError.eLiftET
        salt = identifierBytes ++ (0 +: saltInput)
        dkLen = self.encryption.blockSize
      yield
        (saltInput, iterationCount)
    eitherT.value
}
