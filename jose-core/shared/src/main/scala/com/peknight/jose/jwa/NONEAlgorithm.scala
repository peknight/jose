package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.{Algorithm, NONE}
import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional

object NONEAlgorithm extends JWSAlgorithm:
  val algorithm: Algorithm = NONE
  val requirement: Requirement = Optional
end NONEAlgorithm
