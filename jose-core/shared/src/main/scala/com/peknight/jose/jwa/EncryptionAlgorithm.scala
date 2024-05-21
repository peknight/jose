package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.{Algorithm, NONE}

trait EncryptionAlgorithm:
  def algorithm: Algorithm
  def requirement: Requirement
  def enc: String =
    algorithm match
      case NONE => "none"
      case _ => algorithm.abbreviation
end EncryptionAlgorithm