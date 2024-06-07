package com.peknight.jose.jwa

import com.peknight.jose.Requirement
import com.peknight.security.algorithm.Algorithm

/**
 * https://datatracker.ietf.org/doc/html/rfc7518
 */
trait JsonWebAlgorithm extends Algorithm:
  def requirement: Requirement
end JsonWebAlgorithm
