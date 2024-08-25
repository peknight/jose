package com.peknight.jose.error

trait UnsupportedKeyAlgorithm extends JoseError:
  def algorithm: String
  override protected def lowPriorityMessage: Option[String] = Some(s"Unsupported key algorithm: $algorithm")
end UnsupportedKeyAlgorithm
object UnsupportedKeyAlgorithm:
  private case class UnsupportedKeyAlgorithm(algorithm: String) extends com.peknight.jose.error.UnsupportedKeyAlgorithm
  def apply(algorithm: String): com.peknight.jose.error.UnsupportedKeyAlgorithm = UnsupportedKeyAlgorithm(algorithm)
end UnsupportedKeyAlgorithm
