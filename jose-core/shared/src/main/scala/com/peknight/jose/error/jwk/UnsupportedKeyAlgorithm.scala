package com.peknight.jose.error.jwk

trait UnsupportedKeyAlgorithm extends JsonWebKeyError:
  def algorithm: String
  override protected def lowPriorityMessage: Option[String] = Some(s"Unsupported key algorithm: $algorithm")
end UnsupportedKeyAlgorithm
object UnsupportedKeyAlgorithm:
  private case class UnsupportedKeyAlgorithm(algorithm: String) extends com.peknight.jose.error.jwk.UnsupportedKeyAlgorithm
  def apply(algorithm: String): com.peknight.jose.error.jwk.UnsupportedKeyAlgorithm = UnsupportedKeyAlgorithm(algorithm)
end UnsupportedKeyAlgorithm
