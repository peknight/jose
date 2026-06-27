package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.AES_192
import com.peknight.security.oid.ObjectIdentifier

object A192GCM extends AES_192 with AESGCMAlgorithm:
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.26"))
end A192GCM
