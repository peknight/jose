package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.algorithm.NONE

object none extends JWSAlgorithm with NONE:
  val requirement: Requirement = Optional
  override def algorithm: String = "none"
end none
