package com.peknight.jose.jwa.signature

import com.peknight.jose.jwa.ecc.{Curve, `P-521`}
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-512`}
import com.peknight.security.oid.ObjectIdentifier

object ES512 extends ECDSAAlgorithm:
  val curve: Curve = `P-521`
  val digest: MessageDigestAlgorithm = `SHA-512`
  override def signatureByteLength: Int = 132
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.10045.4.3.4"))
end ES512
