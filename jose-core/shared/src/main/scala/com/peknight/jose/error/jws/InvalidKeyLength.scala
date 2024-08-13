package com.peknight.jose.error.jws

trait InvalidKeyLength extends JsonWebSignatureError:
  def bitLength: Int
  def minimumLength: Int
end InvalidKeyLength
