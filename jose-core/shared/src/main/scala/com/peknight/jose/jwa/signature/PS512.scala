package com.peknight.jose.jwa.signature

import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-512`}

object PS512 extends `RSASSA-PSSAlgorithm`:
  def digest: MessageDigestAlgorithm = `SHA-512`
end PS512
