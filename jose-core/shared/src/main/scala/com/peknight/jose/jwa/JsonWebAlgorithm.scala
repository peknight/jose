package com.peknight.jose.jwa

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import com.peknight.codec.sum.StringType
import com.peknight.jose.Requirement
import com.peknight.jose.jwa.encryption.JWEAlgorithm
import com.peknight.jose.jwa.signature.JWSAlgorithm
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.error.UnknownAlgorithm

import scala.reflect.ClassTag

/**
 * https://datatracker.ietf.org/doc/html/rfc7518
 */
trait JsonWebAlgorithm extends Algorithm:
  def requirement: Requirement
end JsonWebAlgorithm
object JsonWebAlgorithm:
  def stringCodecAlgorithm[F[_]: Applicative, A <: Algorithm : ClassTag](values: List[A])
  : Codec[F, String, String, A] =
    Codec.applicative[F, String, String, A](_.algorithm)(algorithm =>
      values.find(_.algorithm == algorithm).toRight(DecodingFailure(UnknownAlgorithm(algorithm)))
    )

  val values: List[JsonWebAlgorithm] = JWSAlgorithm.values ::: JWEAlgorithm.values
  given stringCodecJsonWebAlgorithm[F[_]: Applicative]: Codec[F, String, String, JsonWebAlgorithm] =
    stringCodecAlgorithm[F, JsonWebAlgorithm](values)
  given codecJsonWebAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], JsonWebAlgorithm] =
    Codec.codecS[F, S, JsonWebAlgorithm]
end JsonWebAlgorithm
