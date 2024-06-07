package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.{Optional, Recommended}
import com.peknight.security.cipher.AESWrap_192

object A192KW extends AESWrapAlgorithm with AESWrap_192:
  val requirement: Requirement = Optional
end A192KW
