package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwk.KeyType.EllipticCurve

trait ECDSA extends JWSAlgorithm with com.peknight.security.signature.ECDSA with ECDSAPlatform:
  def curve: Curve
  override def identifier: String = s"ES${digest.bitLength}"
  def keyType: Option[KeyType] = Some(EllipticCurve)
end ECDSA
object ECDSA:
  val values: List[ECDSA] = List(ES256, ES384, ES512, ES256K)
  given stringCodecECDSA[F[_]: Applicative]: Codec[F, String, String, ECDSA] =
    stringCodecAlgorithmIdentifier[F, ECDSA](values)
  given codecECDSA[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], ECDSA] =
    Codec.codecS[F, S, ECDSA]
end ECDSA
