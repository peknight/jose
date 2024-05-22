package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.{Algorithm, NONE}
import com.peknight.jose.Requirement

trait EncryptionAlgorithm:
  def algorithm: Algorithm
  def requirement: Requirement
  def enc: String =
    algorithm match
      case NONE => "none"
      case _ => algorithm.abbreviation
end EncryptionAlgorithm
