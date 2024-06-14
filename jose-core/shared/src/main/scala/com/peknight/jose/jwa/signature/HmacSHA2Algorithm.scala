package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.mac.HmacSHA2
import com.peknight.security.oid.ObjectIdentifier

trait HmacSHA2Algorithm extends JWSAlgorithm:
  def mac: HmacSHA2
  def algorithm: String = s"HS${mac.digest.bitLength}"
  override def oid: Option[ObjectIdentifier] = mac.oid
end HmacSHA2Algorithm
object HmacSHA2Algorithm:
  val values: List[HmacSHA2Algorithm] = List(HS256, HS384, HS512)
  given stringCodecHmacSHA2Algorithm[F[_]: Applicative]: Codec[F, String, String, HmacSHA2Algorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, HmacSHA2Algorithm](values)
  given codecHmacSHA2Algorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], HmacSHA2Algorithm] =
    Codec.codecS[F, S, HmacSHA2Algorithm]
end HmacSHA2Algorithm
