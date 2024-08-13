package com.peknight.jose.error.jws

import com.peknight.jose.jwa.JsonWebAlgorithm

case class InvalidRSAKeyLength(bitLength: Int, minimumLength: Int)
  extends InvalidKeyLength:
  override def lowPriorityMessage: Option[String] =
    Some(s"An RSA key of size $minimumLength bits or larger MUST be used with the all JOSE RSA algorithms (given key was only $bitLength bits).")
end InvalidRSAKeyLength
