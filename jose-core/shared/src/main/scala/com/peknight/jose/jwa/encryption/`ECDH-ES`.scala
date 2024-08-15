package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.`Recommended+`
import com.peknight.security.oid.ObjectIdentifier

object `ECDH-ES` extends `ECDH-ESAlgorithm`:
  val requirement: Requirement = `Recommended+`
  override val algorithm: String = "ECDH-ES"
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.3.132.1.12"))
end `ECDH-ES`
