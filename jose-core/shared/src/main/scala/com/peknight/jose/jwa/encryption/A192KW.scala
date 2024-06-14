package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.cipher.{AESWrap, AESWrap_192}
import com.peknight.security.oid.ObjectIdentifier

object A192KW extends AESWrapAlgorithm:
  val encryption: AESWrap = AESWrap_192
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.25"))
end A192KW
