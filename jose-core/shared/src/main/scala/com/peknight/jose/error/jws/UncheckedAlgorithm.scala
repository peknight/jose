package com.peknight.jose.error.jws

import com.peknight.jose.jwa.JsonWebAlgorithm

case class UncheckedAlgorithm(algorithm: JsonWebAlgorithm) extends JsonWebSignatureError:
  override def lowPriorityMessage: Option[String] = Some(s"Unchecked algorithm: ${algorithm.algorithm}")
end UncheckedAlgorithm
