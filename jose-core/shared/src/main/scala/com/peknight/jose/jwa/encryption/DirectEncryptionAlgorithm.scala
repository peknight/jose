package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended

trait DirectEncryptionAlgorithm extends JWEAlgorithm:
  def algorithm: String = "dir"
  def headerParams: Seq[HeaderParam] = Seq.empty
  def requirement: Requirement = Recommended
end DirectEncryptionAlgorithm
