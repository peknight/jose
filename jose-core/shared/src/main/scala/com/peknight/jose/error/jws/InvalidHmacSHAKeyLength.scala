package com.peknight.jose.error.jws

import com.peknight.jose.jwa.JsonWebAlgorithm

case class InvalidHmacSHAKeyLength(algorithm: JsonWebAlgorithm, bitLength: Int, minimumLength: Int)
  extends InvalidKeyLength:
  override def lowPriorityMessage: Option[String] =
    Some(s"A key of the same size as the hash output (i.e. $minimumLength bits for ${algorithm.algorithm}) or larger MUST be used with the HMAC SHA algorithms but this key is only $bitLength bits")
end InvalidHmacSHAKeyLength
