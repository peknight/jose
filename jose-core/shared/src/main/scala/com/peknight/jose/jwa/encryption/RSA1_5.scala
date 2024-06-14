package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.`Recommended-`
import com.peknight.security.cipher.{RSAES, `RSAES-PKCS1-v1_5`}
import com.peknight.security.oid.ObjectIdentifier

object RSA1_5 extends RSAESAlgorithm:
  val encryption: RSAES = `RSAES-PKCS1-v1_5`
  val requirement: Requirement = `Recommended-`
  override val algorithm: String = "RSA1_5"
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.1"))
end RSA1_5
