package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.security.algorithm.Algorithm

trait EncryptionAlgorithm extends Algorithm:
  def requirement: Requirement
end EncryptionAlgorithm
