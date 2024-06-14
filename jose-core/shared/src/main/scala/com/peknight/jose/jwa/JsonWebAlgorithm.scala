package com.peknight.jose.jwa

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.Requirement
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
end JsonWebAlgorithm
