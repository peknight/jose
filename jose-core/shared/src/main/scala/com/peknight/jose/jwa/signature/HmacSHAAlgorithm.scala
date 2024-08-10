package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.mac.HmacSHA
import com.peknight.security.oid.ObjectIdentifier

trait HmacSHAAlgorithm extends JWSAlgorithm:
  def mac: HmacSHA
  def algorithm: String = s"HS${mac.digest.bitLength}"
  override def oid: Option[ObjectIdentifier] = mac.oid
end HmacSHAAlgorithm
object HmacSHAAlgorithm:
  val values: List[HmacSHAAlgorithm] = List(HS256, HS384, HS512)
  given stringCodecHmacSHA2Algorithm[F[_]: Applicative]: Codec[F, String, String, HmacSHAAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, HmacSHAAlgorithm](values)
  given codecHmacSHA2Algorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], HmacSHAAlgorithm] =
    Codec.codecS[F, S, HmacSHAAlgorithm]
end HmacSHAAlgorithm
