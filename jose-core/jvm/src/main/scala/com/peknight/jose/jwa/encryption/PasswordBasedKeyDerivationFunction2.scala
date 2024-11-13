package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.{Foldable, Monad}
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.cats.instances.scodec.bits.byteVector.given
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.label
import com.peknight.security.mac.{Hmac, MACAlgorithm}
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpec
import com.peknight.security.syntax.mac.{doFinalF, getMacLengthF, initF}
import com.peknight.validation.spire.math.interval.either.atOrBelow
import fs2.Stream
import scodec.bits.ByteVector

import java.security.Provider as JProvider
import javax.crypto.Mac

object PasswordBasedKeyDerivationFunction2:

  private[encryption] def derive[F[_]: Sync](prf: MACAlgorithm, password: ByteVector, salt: ByteVector,
                                             iterationCount: Int, dkLen: Int, provider: Option[Provider | JProvider]
                                            ): EitherT[F, Error, ByteVector] =
    for
      prf <- EitherT(prf.getMAC[F](provider).asError)
      _ <- EitherT(prf.initF[F](SecretKeySpec(password, Hmac)).asError)
      hLen <- EitherT(prf.getMacLengthF[F].asError)
      //  1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
      //     stop.
      // value of (Math.pow(2, 32) - 1).toLong
      maxDerivedKeyLength = 4294967295L
      _ <- atOrBelow(dkLen.toLong, maxDerivedKeyLength).label("derivedKey").eLiftET
      //  2. Let l be the number of hLen-octet blocks in the derived key,
      //     rounding up, and let r be the number of octets in the last
      //     block:
      //
      //               l = CEIL (dkLen / hLen) ,
      //               r = dkLen - (l - 1) * hLen .
      //
      //     Here, CEIL (x) is the "ceiling" function, i.e. the smallest
      //     integer greater than, or equal to, x.
      l = Math.ceil(dkLen.toDouble / hLen.toDouble).toInt
      r = dkLen - (l - 1) * hLen
      //  3. For each block of the derived key apply the function F defined
      //     below to the password P, the salt S, the iteration count c, and
      //     the block index to compute the block:
      //
      //               T_1 = F (P, S, c, 1) ,
      //               T_2 = F (P, S, c, 2) ,
      //               ...
      //               T_l = F (P, S, c, l) ,
      //
      //     where the function F is defined as the exclusive-or sum of the
      //     first c iterates of the underlying pseudorandom function PRF
      //     applied to the password P and the concatenation of the salt S
      //     and the block index i:
      //
      //               F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
      //
      //     where
      //
      //               U_1 = PRF (P, S || INT (i)) ,
      //               U_2 = PRF (P, U_1) ,
      //               ...
      //               U_c = PRF (P, U_{c-1}) .
      //
      //     Here, INT (i) is a four-octet encoding of the integer i, most
      //     significant octet first.
      //  4. Concatenate the blocks and extract the first dkLen octets to
      //     produce a derived key DK:
      //
      //               DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
      //
      byteVectors <- EitherT(Stream.emits(0 until l).evalMap[F, ByteVector] { i =>
        derive[F](salt, iterationCount, i + 1, prf).map(block => if i == l - 1 then block.take(r) else block)
      }.compile.toList.asError)
    yield
      //  5. Output the derived key DK.
      Foldable[List].fold[ByteVector](byteVectors)

  private def derive[F[_]: Sync](salt: ByteVector, iterationCount: Int, blockIndex: Int, prf: Mac): F[ByteVector] =
    def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] =
      for i <- a.indices do b(i) = (a(i) ^ b(i)).toByte
      b
    prf.doFinalF[F](salt ++ ByteVector.fromInt(blockIndex)).flatMap { currentU =>
      val currentUBytes = currentU.toArray
      Monad[F].tailRecM[(Int, Array[Byte], Array[Byte]), ByteVector]((2, currentUBytes, currentUBytes)) {
        case (i, _, xorU) if i > iterationCount => ByteVector(xorU).asRight.pure
        case (i, lastU, xorU) =>
          Sync[F].blocking(prf.doFinal(lastU)).map(currentU => (i + 1, currentU, xor(currentU, xorU)).asLeft)
      }
    }

end PasswordBasedKeyDerivationFunction2
