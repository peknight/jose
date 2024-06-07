package com.peknight.jose.jwa.signature

import com.peknight.security.digest.{`SHA-2`, `SHA-512`}

object PS512 extends `RSASSA-PSSAlgorithm`:
  def digest: `SHA-2` = `SHA-512`
end PS512
