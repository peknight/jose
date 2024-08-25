package com.peknight.jose.error

import com.peknight.jose.jwa.JsonWebAlgorithm

case class UnsupportedSignatureAlgorithm(algorithm: JsonWebAlgorithm) extends JoseError:
  override def lowPriorityMessage: Option[String] = Some(s"Unsupported JWS algorithm: ${algorithm.algorithm}")
end UnsupportedSignatureAlgorithm
