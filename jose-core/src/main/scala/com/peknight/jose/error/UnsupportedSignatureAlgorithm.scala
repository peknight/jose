package com.peknight.jose.error

import com.peknight.jose.jwa.JsonWebAlgorithm

trait UnsupportedSignatureAlgorithm extends JoseError:
  def algorithm: JsonWebAlgorithm
  override def lowPriorityMessage: Option[String] = Some(s"Unsupported JWS algorithm: ${algorithm.algorithm}")
end UnsupportedSignatureAlgorithm
object UnsupportedSignatureAlgorithm:
  private case class UnsupportedSignatureAlgorithm(algorithm: JsonWebAlgorithm)
    extends com.peknight.jose.error.UnsupportedSignatureAlgorithm
  def apply(algorithm: JsonWebAlgorithm): com.peknight.jose.error.UnsupportedSignatureAlgorithm =
    UnsupportedSignatureAlgorithm(algorithm)
end UnsupportedSignatureAlgorithm
