package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.{AESWrap, AESWrap_256}

object A256KW extends AESWrapAlgorithm:
  val encryption: AESWrap = AESWrap_256
  val requirement: Requirement = Recommended
end A256KW
