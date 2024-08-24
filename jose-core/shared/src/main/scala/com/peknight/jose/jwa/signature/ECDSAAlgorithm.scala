package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.security.signature.ECDSA

trait ECDSAAlgorithm extends JWSAlgorithm with ECDSA:
  def curve: Curve
  override def identifier: String = s"ES${digest.bitLength}"
end ECDSAAlgorithm
object ECDSAAlgorithm:
  val values: List[ECDSAAlgorithm] = List(ES256, ES384, ES512)
  given stringCodecECDSAAlgorithm[F[_]: Applicative]: Codec[F, String, String, ECDSAAlgorithm] =
    stringCodecAlgorithmIdentifier[F, ECDSAAlgorithm](values)
  given codecECDSAAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], ECDSAAlgorithm] =
    Codec.codecS[F, S, ECDSAAlgorithm]
end ECDSAAlgorithm
