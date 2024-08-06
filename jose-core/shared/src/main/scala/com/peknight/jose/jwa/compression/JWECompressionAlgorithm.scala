package com.peknight.jose.jwa.compression

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.algorithm.Algorithm

trait JWECompressionAlgorithm extends Algorithm
object JWECompressionAlgorithm:
  val values: List[JWECompressionAlgorithm] = List(Deflate)
  given stringCodecJWECompressionAlgorithm[F[_]: Applicative]: Codec[F, String, String, JWECompressionAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, JWECompressionAlgorithm](values)
  given codecJWECompressionAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], JWECompressionAlgorithm] =
    Codec.codecS[F, S, JWECompressionAlgorithm]
end JWECompressionAlgorithm
