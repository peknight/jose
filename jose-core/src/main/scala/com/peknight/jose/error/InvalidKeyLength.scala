package com.peknight.jose.error

trait InvalidKeyLength extends JoseError:
  def algorithm: String
  def expectedBitLength: Int
  def actualBitLength: Int
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Invalid key length for $algorithm, expected a $expectedBitLength bit key but a $actualBitLength bit key was provided")
end InvalidKeyLength
object InvalidKeyLength:
  private case class InvalidKeyLength(algorithm: String, expectedBitLength: Int, actualBitLength: Int)
    extends com.peknight.jose.error.InvalidKeyLength
  def apply(algorithm: String, expectedBitLength: Int, actualBitLength: Int): com.peknight.jose.error.InvalidKeyLength =
    InvalidKeyLength(algorithm, expectedBitLength, actualBitLength)
end InvalidKeyLength
