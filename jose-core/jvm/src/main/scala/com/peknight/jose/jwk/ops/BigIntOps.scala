package com.peknight.jose.jwk.ops

import cats.Applicative
import cats.syntax.functor.*
import com.peknight.codec.base.{Base, BaseAlphabetPlatform}
import com.peknight.codec.error.DecodingFailure
import scodec.bits.Bases.Alphabet
import scodec.bits.ByteVector

object BigIntOps:
  def fromBytes(magnitude: ByteVector): BigInt = BigInt(1, magnitude.toArray)
  def fromBase[F[_]: Applicative](base: Base): F[Either[DecodingFailure, BigInt]] =
    base.decode[F].map(_.map(fromBytes))
  def toBytes(bigInt: BigInt, minLength: Int): ByteVector =
    val notPadded = toBytesUnsigned(bigInt)
    if notPadded.length >= minLength then notPadded
    else ByteVector.fill(minLength - notPadded.length)(0) ++ notPadded
  def toBytesUnsigned(bigInt: BigInt): ByteVector =
    val bitLen = ((bigInt.bitLength + 7) >> 3) << 3
    val bigBytes = ByteVector(bigInt.toByteArray)
    if bigInt.bitLength % 8 != 0 && (bigInt.bitLength / 8) + 1 == bitLen / 8 then
      bigBytes
    else
      val src = if bigInt.bitLength % 8 == 0 then bigBytes.tail else bigBytes
      val startDst = bitLen / 8 - src.length
      ByteVector.fill(startDst)(0) ++ src
  def toBase[A <: Alphabet, B <: Base](bigInt: BigInt, minLength: Int, platform: BaseAlphabetPlatform[A, B]): B =
    platform.fromByteVector(toBytes(bigInt, minLength))
  def toBase[A <: Alphabet, B <: Base](bigInt: BigInt, platform: BaseAlphabetPlatform[A, B]): B =
    platform.fromByteVector(BigIntOps.toBytesUnsigned(bigInt))
end BigIntOps
