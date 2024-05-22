package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.signature.DigestWithEncryption
import com.peknight.jose.Requirement

trait RSA_PSSAlgorithm extends RSAAlgorithm
object RSA_PSSAlgorithm:
  private[this] case class RSA_PSSAlgorithm(algorithm: DigestWithEncryption, requirement: Requirement)
    extends com.peknight.jose.jwa.RSA_PSSAlgorithm
  def apply(algorithm: DigestWithEncryption, requirement: Requirement): com.peknight.jose.jwa.RSA_PSSAlgorithm =
    RSA_PSSAlgorithm(algorithm, requirement)
end RSA_PSSAlgorithm
