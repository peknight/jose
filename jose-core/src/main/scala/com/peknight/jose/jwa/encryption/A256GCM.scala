package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Recommended
import com.peknight.security.cipher.AES_256
import com.peknight.security.oid.ObjectIdentifier

object A256GCM extends AES_256 with AESGCMAlgorithm:
  val requirement: Requirement = Recommended
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.46"))
end A256GCM
