package com.peknight.jose.error.jws

import com.peknight.jose.jwa.JsonWebAlgorithm

case class UnsupportedSignatureAlgorithm(algorithm: JsonWebAlgorithm) extends JsonWebSignatureError:
  override def lowPriorityMessage: Option[String] = Some(s"Unsupported JWS algorithm: ${algorithm.algorithm}")
end UnsupportedSignatureAlgorithm
