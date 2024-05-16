package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.{Algorithm, NONE}
import com.peknight.jose.jwa.Requirement.Optional

object NONEAlgorithm extends JWSAlgorithm:
  val algorithm: Algorithm = NONE
  val requirement: Requirement = Optional
end NONEAlgorithm
