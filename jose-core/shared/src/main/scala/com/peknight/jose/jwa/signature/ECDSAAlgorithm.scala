package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.security.digest.MessageDigestAlgorithm

trait ECDSAAlgorithm extends JWSAlgorithm:
  def curve: Curve
  def digest: MessageDigestAlgorithm
  def algorithm: String = s"ES${digest.bitLength}"
end ECDSAAlgorithm
object ECDSAAlgorithm:
  val values: List[ECDSAAlgorithm] = List(ES256, ES384, ES512)
  given stringCodecECDSAAlgorithm[F[_]: Applicative]: Codec[F, String, String, ECDSAAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, ECDSAAlgorithm](values)
  given codecECDSAAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], ECDSAAlgorithm] =
    Codec.codecS[F, S, ECDSAAlgorithm]
end ECDSAAlgorithm
