package com.peknight.jose.jwa.signature

import com.peknight.jose.jwa.ecc.{Curve, `P-256K`}
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.`Recommended+`
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-256`}
import com.peknight.security.oid.ObjectIdentifier

object ES256K extends ECDSAAlgorithm:
  val curve: Curve = `P-256K`
  val digest: MessageDigestAlgorithm = `SHA-256`
  val requirement: Requirement = `Recommended+`
  override def algorithm: String = "ES256K"
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.10045.4.3.2"))
end ES256K
