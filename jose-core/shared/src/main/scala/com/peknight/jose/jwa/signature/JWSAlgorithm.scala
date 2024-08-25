package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.JsonWebAlgorithm

trait JWSAlgorithm extends JsonWebAlgorithm
object JWSAlgorithm:
  val values: List[JWSAlgorithm] =
    HmacSHA.values :::
      `RSASSA-PKCS1-v1_5`.values :::
      ECDSA.values :::
      `RSASSA-PSS`.values :::
      none :: Nil

  given stringCodecJWSAlgorithm[F[_]: Applicative]: Codec[F, String, String, JWSAlgorithm] =
    stringCodecAlgorithmIdentifier[F, JWSAlgorithm](values)

  given codecJWSAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], JWSAlgorithm] =
    Codec.codecS[F, S, JWSAlgorithm]
end JWSAlgorithm
