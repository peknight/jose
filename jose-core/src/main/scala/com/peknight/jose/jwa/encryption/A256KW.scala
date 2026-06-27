package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Recommended
import com.peknight.security.cipher.AESWrap_256
import com.peknight.security.oid.ObjectIdentifier

object A256KW extends AESWrap_256 with AESWrapAlgorithm:
  val requirement: Requirement = Recommended
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.45"))
end A256KW
