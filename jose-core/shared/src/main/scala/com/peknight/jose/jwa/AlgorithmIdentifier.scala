package com.peknight.jose.jwa

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.error.DecodingFailure
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.error.UnknownAlgorithm

import scala.reflect.ClassTag

trait AlgorithmIdentifier extends Algorithm with AlgorithmIdentifierPlatform:
  def identifier: String = algorithm
  override def toString: String = identifier
end AlgorithmIdentifier
object AlgorithmIdentifier:
  def stringCodecAlgorithmIdentifier[F[_]: Applicative, A <: AlgorithmIdentifier : ClassTag](values: List[A])
  : Codec[F, String, String, A] =
    Codec.applicative[F, String, String, A](_.identifier)(identifier =>
      values.find(_.identifier == identifier).toRight(DecodingFailure(UnknownAlgorithm(identifier)))
    )
end AlgorithmIdentifier
