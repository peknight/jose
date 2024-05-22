package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.cipher.Transformation
import com.peknight.jose.Requirement
import com.peknight.jose.jwa.HeaderParam.{iv, tag}
import com.peknight.jose.Requirement.Optional

trait AESGCMKWAlgorithm extends KeyEncryptionAlgorithm:
  val headerParams: Seq[HeaderParam] = Seq(iv, tag)
  val requirement: Requirement = Optional
end AESGCMKWAlgorithm
object AESGCMKWAlgorithm:
  private[this] case class AESGCMKWAlgorithm(algorithm: Transformation) extends com.peknight.jose.jwa.AESGCMKWAlgorithm
  def apply(algorithm: Transformation): com.peknight.jose.jwa.AESGCMKWAlgorithm = AESGCMKWAlgorithm(algorithm)
end AESGCMKWAlgorithm
