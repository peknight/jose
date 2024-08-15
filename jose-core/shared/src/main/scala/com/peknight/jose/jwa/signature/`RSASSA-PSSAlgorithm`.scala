package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.RSA
import com.peknight.security.digest.`SHA-2`
import com.peknight.security.mgf.{MGF, MGF1}
import com.peknight.security.oid.ObjectIdentifier
import com.peknight.security.signature.DigestWithEncryption

trait `RSASSA-PSSAlgorithm` extends RSASSAAlgorithm with `RSASSA-PSSAlgorithmPlatform`:
  def mgf: MGF = MGF1
  def signature: DigestWithEncryption = digest.withEncryption(RSA, Some(mgf))
  def saltLength: Int = digest.outputLength / 8
  def requirement: Requirement = Optional
  def algorithm: String = s"PS${digest.bitLength}"
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.10"))
end `RSASSA-PSSAlgorithm`
object `RSASSA-PSSAlgorithm`:
  val values: List[`RSASSA-PSSAlgorithm`] = List(PS256, PS384, PS512)
  given `stringCodecRSASSA-PSSAlgorithm`[F[_]: Applicative]: Codec[F, String, String, `RSASSA-PSSAlgorithm`] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, `RSASSA-PSSAlgorithm`](values)
  given `codecRSASSA-PSSAlgorithm`[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], `RSASSA-PSSAlgorithm`] =
    Codec.codecS[F, S, `RSASSA-PSSAlgorithm`]
end `RSASSA-PSSAlgorithm`
