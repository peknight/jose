package com.peknight.jose.error

trait InvalidKeyAlgorithm extends JoseError:
  def algorithm: String
  override protected def lowPriorityMessage: Option[String] = Some(s"Invalid key algorithm: $algorithm")
end InvalidKeyAlgorithm
object InvalidKeyAlgorithm:
  private case class InvalidKeyAlgorithm(algorithm: String) extends com.peknight.jose.error.InvalidKeyAlgorithm
  def apply(algorithm: String): com.peknight.jose.error.InvalidKeyAlgorithm = InvalidKeyAlgorithm(algorithm)
end InvalidKeyAlgorithm
