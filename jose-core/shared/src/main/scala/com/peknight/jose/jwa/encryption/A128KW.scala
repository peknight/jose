package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.AESWrap_128

object A128KW extends AESWrapAlgorithm with AESWrap_128:
  val requirement: Requirement = Recommended
end A128KW
