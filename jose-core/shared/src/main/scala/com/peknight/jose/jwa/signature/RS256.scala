package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Recommended
import com.peknight.security.digest.{`SHA-256`, `SHA-2`}
import com.peknight.security.oid.ObjectIdentifier

object RS256 extends `RSASSA-PKCS1-v1_5Algorithm`:
  val digest: `SHA-2` = `SHA-256`
  val requirement: Requirement = Recommended
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.11"))
end RS256
