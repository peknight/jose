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
    val twosComplementBytes = ByteVector(bigInt.toByteArray)
    if bigInt.bitLength % 8 == 0 && twosComplementBytes.length > 1 && twosComplementBytes.head == 0 then
      twosComplementBytes.tail
    else
      twosComplementBytes
  def toBase[A <: Alphabet, B <: Base](bigInt: BigInt, minLength: Int, platform: BaseAlphabetPlatform[A, B]): B =
    platform.fromByteVector(toBytes(bigInt, minLength))
  def toBase[A <: Alphabet, B <: Base](bigInt: BigInt, platform: BaseAlphabetPlatform[A, B]): B =
    platform.fromByteVector(toBytesUnsigned(bigInt))
end BigIntOps
