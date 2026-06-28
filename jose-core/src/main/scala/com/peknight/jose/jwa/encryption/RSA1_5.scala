package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.`Recommended-`
import com.peknight.security.cipher.padding.{CipherAlgorithmPadding, PKCS1Padding}
import com.peknight.security.cipher.{RSAES, `RSAES-PKCS1-v1_5`}
import com.peknight.security.oid.ObjectIdentifier

object RSA1_5 extends RSAESAlgorithm with `RSAES-PKCS1-v1_5` with RSA1_5Companion:
  override def padding: CipherAlgorithmPadding = PKCS1Padding
  val requirement: Requirement = `Recommended-`
  override val identifier: String = "RSA1_5"
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.1"))
end RSA1_5
