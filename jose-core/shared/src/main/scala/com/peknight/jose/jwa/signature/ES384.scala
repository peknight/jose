package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.jose.jwa.ecc.{Curve, `P-384`}
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-384`}
import com.peknight.security.oid.ObjectIdentifier

object ES384 extends ECDSAAlgorithm:
  val curve: Curve = `P-384`
  val digest: MessageDigestAlgorithm = `SHA-384`
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.10045.4.3.3"))
end ES384
