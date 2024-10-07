package com.peknight.jose.jwa.encryption

import cats.Monad
import cats.data.EitherT
import com.peknight.security.syntax.mac.{getMacLengthF, doFinalF}
import cats.syntax.flatMap.*
import cats.effect.Sync
import com.peknight.error.Error
import fs2.Stream
import scodec.bits.ByteVector
import com.peknight.validation.spire.math.interval.either.{atOrAbove, atOrBelow}
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.{asError, label}
import com.peknight.security.provider.Provider

import java.security.{SecureRandom, Provider as JProvider}
import javax.crypto.Mac

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
        prf <- EitherT(self.prf.getMAC[F](macProvider).asError)
        hLen <- EitherT(prf.getMacLengthF[F].asError)
        // value of (Math.pow(2, 32) - 1).toLong
        maxDerivedKeyLength = 4294967295L
        _ <- atOrBelow(dkLen.toLong, maxDerivedKeyLength).label("derivedKey").eLiftET
        l = Math.ceil(dkLen.toDouble / hLen.toDouble).toInt
        r = dkLen - (l - 1) * hLen
        // _ <- Stream.emits(0 until l).evalMap[F, ByteVector] { i =>
        //
        // }
      yield
        (saltInput, iterationCount)
    eitherT.value

    def f[F[_]: Sync](salt: ByteVector, iterationCount: Int, blockIndex: Int, prf: Mac): F[ByteVector] =
      prf.doFinalF[F](salt ++ ByteVector.fromInt(blockIndex)).flatMap { currentU =>
        Monad[F].tailRecM[(Int, ByteVector, ByteVector), ByteVector]((2, currentU, currentU)) {
          case (i, currentU, xorU) if i => 
        }
      }
}
