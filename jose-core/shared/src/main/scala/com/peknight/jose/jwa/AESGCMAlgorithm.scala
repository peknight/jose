package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.cipher.Transformation
import com.peknight.jose.jwa.HeaderParam.{iv, tag}
import com.peknight.jose.jwa.Requirement.Optional

trait AESGCMAlgorithm extends KeyEncryptionAlgorithm:
  val headerParams: Seq[HeaderParam] = Seq(iv, tag)
  val requirement: Requirement = Optional
end AESGCMAlgorithm
object AESGCMAlgorithm:
  private[this] case class AESGCMAlgorithm(algorithm: Transformation) extends com.peknight.jose.jwa.AESGCMAlgorithm
  def apply(algorithm: Transformation): com.peknight.jose.jwa.AESGCMAlgorithm = AESGCMAlgorithm(algorithm)
end AESGCMAlgorithm
