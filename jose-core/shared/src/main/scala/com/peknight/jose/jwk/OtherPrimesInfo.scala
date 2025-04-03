package com.peknight.jose.jwk

import cats.Monad
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.{NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to

case class OtherPrimesInfo(
                            /**
                             * The "r" (prime factor) parameter within an "oth" array member
                             * represents the value of a subsequent prime factor.  It is represented
                             * as a Base64urlUInt-encoded value.
                             */
                            primeFactor: Base64UrlNoPad,
                            /**
                             * The "d" (factor CRT exponent) parameter within an "oth" array member
                             * represents the CRT exponent of the corresponding prime factor.  It is
                             * represented as a Base64urlUInt-encoded value.
                             */
                            factorCRTExponent: Base64UrlNoPad,
                            /**
                             * The "k" (key value) parameter contains the value of the symmetric (or
                             * other single-valued) key.  It is represented as the base64url
                             * encoding of the octet sequence containing the key value.
                             */
                            factorCRTCoefficient: Base64UrlNoPad
                          )
object OtherPrimesInfo:
  private val memberNameMap: Map[String, String] =
    Map(
      "primeFactor" -> "r",
      "factorCRTExponent" -> "d",
      "factorCRTCoefficient" -> "k"
    )
  given codecOtherPrimesInfo[F[_], S](using
    Monad[F],
    ObjectType[S],
    NullType[S],
    StringType[S]
  ): Codec[F, S, Cursor[S], OtherPrimesInfo] =
    Codec.derived[F, S, OtherPrimesInfo](using CodecConfiguration.default.withTransformMemberName(memberName =>
      memberNameMap.getOrElse(memberName, memberName.to(SnakeCase))
    ))
end OtherPrimesInfo