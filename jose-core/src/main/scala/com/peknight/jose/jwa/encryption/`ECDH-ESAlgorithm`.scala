package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.ecc.{Curve, `P-256`, `P-384`, `P-521`}
import com.peknight.jose.jwa.encryption.HeaderParam.{apu, apv, epk}
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwk.KeyType.{EllipticCurve, OctetKeyPair}
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.`Recommended+`
import com.peknight.security.key.agreement.ECDH
import com.peknight.security.oid.ObjectIdentifier

trait `ECDH-ESAlgorithm` extends KeyAgreementAlgorithm with ECDH with `ECDH-ESAlgorithmPlatform`:
  override def identifier: String = "ECDH-ES"
  val requirement: Requirement = `Recommended+`
  def headerParams: Seq[HeaderParam] = Seq(epk, apu, apv)
  def supportedCurves: List[Curve] = List(`P-256`, `P-384`, `P-521`)
  override def keyTypes: List[KeyType] = List(EllipticCurve, OctetKeyPair)
  private[jose] def canOverrideCek: Boolean = false
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.3.132.1.12"))
end `ECDH-ESAlgorithm`
object `ECDH-ESAlgorithm`:
  val values: List[`ECDH-ESAlgorithm`] = List(`ECDH-ES`)
  given `stringCodecECDH-ESAlgorithm`[F[_]: Applicative]: Codec[F, String, String, `ECDH-ESAlgorithm`] =
    stringCodecAlgorithmIdentifier[F, `ECDH-ESAlgorithm`](values)
  given `codecECDH-ESAlgorithm`[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], `ECDH-ESAlgorithm`] =
    Codec.codecS[F, S, `ECDH-ESAlgorithm`]
end `ECDH-ESAlgorithm`
