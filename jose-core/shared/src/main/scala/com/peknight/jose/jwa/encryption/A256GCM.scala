package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.{AES, AES_256}

object A256GCM extends AESGCMAlgorithm:
  def encryption: AES = AES_256 / GCM
  val requirement: Requirement = Recommended
end A256GCM
