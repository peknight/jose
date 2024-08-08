package com.peknight.jose.key

import cats.Applicative
import cats.syntax.functor.*
import com.peknight.codec.base.Base
import com.peknight.codec.error.DecodingFailure
import scodec.bits.ByteVector

object BigIntOps:
  def fromBytes(magnitude: ByteVector): BigInt = BigInt(1, magnitude.toArray)
  def fromBase[F[_]: Applicative](base: Base): F[Either[DecodingFailure, BigInt]] =
    base.decode[F].map(_.map(fromBytes))
end BigIntOps
