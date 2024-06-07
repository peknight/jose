package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.AES_192

object A192GCM extends AESGCMAlgorithm with AES_192:
  val requirement: Requirement = Recommended
end A192GCM
