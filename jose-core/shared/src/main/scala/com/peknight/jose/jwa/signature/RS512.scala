package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.digest.{`SHA-2`, `SHA-512`}
import com.peknight.security.oid.ObjectIdentifier

object RS512 extends `RSASSA-PKCS1-v1_5Algorithm`:
  val digest: `SHA-2` = `SHA-512`
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.13"))
end RS512
