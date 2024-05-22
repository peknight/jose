package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.cipher.Transformation
import com.peknight.jose.Requirement

trait RSAOAEPAlgorithm extends KeyEncryptionAlgorithm:
  val headerParams: Seq[HeaderParam] = Seq.empty[HeaderParam]
end RSAOAEPAlgorithm

object RSAOAEPAlgorithm:
  private[this] case class RSAOAEPAlgorithm(algorithm: Transformation, requirement: Requirement)
    extends com.peknight.jose.jwa.RSAOAEPAlgorithm
  def apply(algorithm: Transformation, requirement: Requirement): com.peknight.jose.jwa.RSAOAEPAlgorithm =
    RSAOAEPAlgorithm(algorithm, requirement)
end RSAOAEPAlgorithm
