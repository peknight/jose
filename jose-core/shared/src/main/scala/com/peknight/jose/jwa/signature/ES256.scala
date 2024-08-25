package com.peknight.jose.jwa.signature

import com.peknight.jose.jwa.ecc.{Curve, `P-256`}
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.`Recommended+`
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-256`}
import com.peknight.security.oid.ObjectIdentifier

object ES256 extends ECDSA:
  val curve: Curve = `P-256`
  val digest: MessageDigestAlgorithm = `SHA-256`
  val requirement: Requirement = `Recommended+`
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.10045.4.3.2"))
end ES256
