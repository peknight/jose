package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.{AES, AES_192}
import com.peknight.security.oid.ObjectIdentifier

object A192GCM extends AESGCMAlgorithm:
  def encryption: AES = AES_192 / GCM
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.26"))
end A192GCM
