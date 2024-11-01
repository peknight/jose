package com.peknight.jose.jwa.compression

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier


trait CompressionAlgorithm extends AlgorithmIdentifier with CompressionAlgorithmPlatform
object CompressionAlgorithm:
  val values: List[CompressionAlgorithm] = List(Deflate)
  given stringCodecJWECompressionAlgorithm[F[_]: Applicative]: Codec[F, String, String, CompressionAlgorithm] =
    stringCodecAlgorithmIdentifier[F, CompressionAlgorithm](values)
  given codecJWECompressionAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], CompressionAlgorithm] =
    Codec.codecS[F, S, CompressionAlgorithm]
end CompressionAlgorithm
