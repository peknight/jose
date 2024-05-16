package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.{Algorithm, NONE}

/**
 * https://www.ietf.org/rfc/rfc7518.html
 */
trait JsonWebAlgorithm:
  def algorithm: Algorithm
  def requirement: Requirement
  def alg: String =
    algorithm match
      case NONE => "none"
      case _ => algorithm.abbreviation
end JsonWebAlgorithm
