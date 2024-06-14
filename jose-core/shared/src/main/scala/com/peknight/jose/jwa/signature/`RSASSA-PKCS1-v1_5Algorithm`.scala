package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.digest.`SHA-2`

trait `RSASSA-PKCS1-v1_5Algorithm` extends JWSAlgorithm:
  def digest: `SHA-2`
  def algorithm: String = s"RS${digest.bitLength}"
end `RSASSA-PKCS1-v1_5Algorithm`
object `RSASSA-PKCS1-v1_5Algorithm`:
  val values: List[`RSASSA-PKCS1-v1_5Algorithm`] = List(RS256, RS384, RS512)
  given `stringCodecRSASSA-PKCS1-v1_5Algorithm`[F[_]: Applicative]
  : Codec[F, String, String, `RSASSA-PKCS1-v1_5Algorithm`] = 
    JsonWebAlgorithm.stringCodecAlgorithm[F, `RSASSA-PKCS1-v1_5Algorithm`](values)
  given `codecRSASSA-PKCS1-v1_5Algorithm`[F[_]: Applicative, S: StringType]
  : Codec[F, S, Cursor[S], `RSASSA-PKCS1-v1_5Algorithm`] =
    Codec.codecS[F, S, `RSASSA-PKCS1-v1_5Algorithm`]
end `RSASSA-PKCS1-v1_5Algorithm`
