package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.AES_128

object A128GCM extends AESGCMAlgorithm with AES_128:
  val requirement: Requirement = Recommended
end A128GCM
