package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.cipher.{AESWrap, AESWrap_192}

object A192KW extends AESWrapAlgorithm:
  val encryption: AESWrap = AESWrap_192
  val requirement: Requirement = Optional
end A192KW
