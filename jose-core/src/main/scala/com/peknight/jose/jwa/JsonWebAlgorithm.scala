package com.peknight.jose.jwa

import cats.{Applicative, Eq, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.encryption.JWEAlgorithm
import com.peknight.jose.jwa.signature.JWSAlgorithm
import com.peknight.jose.jwx.Requirement

import scala.reflect.ClassTag

/**
 * https://datatracker.ietf.org/doc/html/rfc7518
 */
trait JsonWebAlgorithm extends AlgorithmIdentifier:
  def requirement: Requirement
end JsonWebAlgorithm
object JsonWebAlgorithm:
  val values: List[JsonWebAlgorithm] = JWSAlgorithm.values ::: JWEAlgorithm.values
  given Eq[JsonWebAlgorithm] = Eq.fromUniversalEquals
  given stringCodecJsonWebAlgorithm[F[_]: Applicative]: Codec[F, String, String, JsonWebAlgorithm] =
    stringCodecAlgorithmIdentifier[F, JsonWebAlgorithm](values)
  given codecJsonWebAlgorithm[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], JsonWebAlgorithm] =
    Codec.codecS[F, S, JsonWebAlgorithm]
end JsonWebAlgorithm
