package com.peknight.jose.jwa.signature

import com.peknight.security.digest.{`SHA-2`, `SHA-384`}

object PS384 extends `RSASSA-PSSAlgorithm`:
  def digest: `SHA-2` = `SHA-384`
end PS384
