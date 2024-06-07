package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.AES_256

object A256GCM extends AESGCMAlgorithm with AES_256:
  val requirement: Requirement = Recommended
end A256GCM
