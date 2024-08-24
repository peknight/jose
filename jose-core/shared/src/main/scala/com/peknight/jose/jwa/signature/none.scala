package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional

object none extends JWSAlgorithm with com.peknight.security.algorithm.NONE:
  val requirement: Requirement = Optional
  override def identifier: String = "none"
end none
