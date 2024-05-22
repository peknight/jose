package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.cipher.symmetric.AESWrap
import com.peknight.jose.Requirement

trait AESKeyWrapAlgorithm extends KeyWrappingAlgorithm:
  val headerParams: Seq[HeaderParam] = Seq.empty[HeaderParam]
end AESKeyWrapAlgorithm
object AESKeyWrapAlgorithm:
  private[this] case class AESKeyWrapAlgorithm(algorithm: AESWrap, requirement: Requirement)
    extends com.peknight.jose.jwa.AESKeyWrapAlgorithm
  def apply(algorithm: AESWrap, requirement: Requirement): com.peknight.jose.jwa.AESKeyWrapAlgorithm =
    AESKeyWrapAlgorithm(algorithm, requirement)
end AESKeyWrapAlgorithm
