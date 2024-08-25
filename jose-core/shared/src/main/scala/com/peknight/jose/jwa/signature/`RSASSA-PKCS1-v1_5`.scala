package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier

trait `RSASSA-PKCS1-v1_5` extends RSASSA with com.peknight.security.signature.`RSASSA-PKCS1-v1_5`
  with `RSASSA-PKCS1-v1_5Platform`:
  override def identifier: String = s"RS${digest.bitLength}"
end `RSASSA-PKCS1-v1_5`
object `RSASSA-PKCS1-v1_5`:
  val values: List[`RSASSA-PKCS1-v1_5`] = List(RS256, RS384, RS512)
  given `stringCodecRSASSA-PKCS1-v1_5`[F[_]: Applicative]: Codec[F, String, String, `RSASSA-PKCS1-v1_5`] =
    stringCodecAlgorithmIdentifier[F, `RSASSA-PKCS1-v1_5`](values)
  given `codecRSASSA-PKCS1-v1_5`[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], `RSASSA-PKCS1-v1_5`] =
    Codec.codecS[F, S, `RSASSA-PKCS1-v1_5`]
end `RSASSA-PKCS1-v1_5`
