package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.{AES, AES_256}
import com.peknight.security.oid.ObjectIdentifier

object A256GCM extends AESGCMAlgorithm:
  def encryption: AES = AES_256 / GCM
  val requirement: Requirement = Recommended
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.46"))
end A256GCM
