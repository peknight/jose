package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.{AES, AES_192}

object A192GCM extends AESGCMAlgorithm:
  def encryption: AES = AES_192 / GCM
  val requirement: Requirement = Optional
end A192GCM
