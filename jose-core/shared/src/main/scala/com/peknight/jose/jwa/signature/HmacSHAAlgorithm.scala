package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.mac.HmacSHA
import com.peknight.security.oid.ObjectIdentifier

trait HmacSHAAlgorithm extends JWSAlgorithm with HmacSHA:
  override def identifier: String = s"HS${digest.bitLength}"
end HmacSHAAlgorithm
object HmacSHAAlgorithm:
  val values: List[HmacSHAAlgorithm] = List(HS256, HS384, HS512)
  given stringCodecHmacSHA2Algorithm[F[_]: Applicative]: Codec[F, String, String, HmacSHAAlgorithm] =
    stringCodecAlgorithmIdentifier[F, HmacSHAAlgorithm](values)
  given codecHmacSHA2Algorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], HmacSHAAlgorithm] =
    Codec.codecS[F, S, HmacSHAAlgorithm]
end HmacSHAAlgorithm
