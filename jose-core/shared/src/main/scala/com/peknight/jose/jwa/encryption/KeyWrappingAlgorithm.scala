package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier

trait KeyWrappingAlgorithm extends KeyManagementAlgorithm
object KeyWrappingAlgorithm:
  val values: List[KeyWrappingAlgorithm] = AESWrapAlgorithm.values
  given stringCodecKeyWrappingAlgorithm[F[_]: Applicative]: Codec[F, String, String, KeyWrappingAlgorithm] =
    stringCodecAlgorithmIdentifier[F, KeyWrappingAlgorithm](values)
  given codecKeyWrappingAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], KeyWrappingAlgorithm] =
    Codec.codecS[F, S, KeyWrappingAlgorithm]
end KeyWrappingAlgorithm
