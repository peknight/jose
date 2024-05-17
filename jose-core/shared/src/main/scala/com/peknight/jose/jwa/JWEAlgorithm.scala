package com.peknight.jose.jwa

trait JWEAlgorithm extends JsonWebAlgorithm:
  def headerParams: Seq[HeaderParam]
end JWEAlgorithm
