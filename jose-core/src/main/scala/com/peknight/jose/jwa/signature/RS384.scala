package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-384`}
import com.peknight.security.oid.ObjectIdentifier

object RS384 extends `RSASSA-PKCS1-v1_5`:
  val digest: MessageDigestAlgorithm = `SHA-384`
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.12"))
end RS384
