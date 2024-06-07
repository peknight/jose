package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwa.JsonWebAlgorithm

trait JWEAlgorithm extends JsonWebAlgorithm:
  def headerParams: Seq[HeaderParam]
end JWEAlgorithm

