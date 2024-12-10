package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwk.KeyType.OctetSequence
import com.peknight.security.mac.HmacSHA
import com.peknight.security.oid.ObjectIdentifier

trait HmacSHA extends JWSAlgorithm with com.peknight.security.mac.HmacSHA with HmacSHAPlatform:
  override def identifier: String = s"HS${digest.bitLength}"
  def keyType: Option[KeyType] = Some(OctetSequence)
end HmacSHA
object HmacSHA:
  val values: List[HmacSHA] = List(HS256, HS384, HS512)
  given stringCodecHmacSHA[F[_]: Applicative]: Codec[F, String, String, HmacSHA] =
    stringCodecAlgorithmIdentifier[F, HmacSHA](values)
  given codecHmacSHA[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], HmacSHA] =
    Codec.codecS[F, S, HmacSHA]
end HmacSHA
