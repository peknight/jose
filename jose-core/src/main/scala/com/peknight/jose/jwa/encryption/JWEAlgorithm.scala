package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.JsonWebAlgorithm

trait JWEAlgorithm extends JsonWebAlgorithm:
  def headerParams: Seq[HeaderParam]
end JWEAlgorithm
object JWEAlgorithm:
  val values: List[JWEAlgorithm] = KeyManagementAlgorithm.values
  given stringCodecJWEAlgorithm[F[_]: Applicative]: Codec[F, String, String, JWEAlgorithm] =
    stringCodecAlgorithmIdentifier[F, JWEAlgorithm](values)
  given codecJWEAlgorithm[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], JWEAlgorithm] =
    Codec.codecS[F, S, JWEAlgorithm]
end JWEAlgorithm
