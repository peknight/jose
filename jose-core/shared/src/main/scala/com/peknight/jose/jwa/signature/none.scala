package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional

object none extends JWSAlgorithm:
  val requirement: Requirement = Optional
  override def algorithm: String = "none"
end none
