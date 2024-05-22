package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.Algorithm
import com.peknight.crypto.algorithm.cipher.symmetric.Direct
import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended

object DirectAlgorithm extends JWEAlgorithm:
  val algorithm: Algorithm = Direct
  val headerParams: Seq[HeaderParam] = Seq.empty[HeaderParam]
  val requirement: Requirement = Recommended
end DirectAlgorithm
