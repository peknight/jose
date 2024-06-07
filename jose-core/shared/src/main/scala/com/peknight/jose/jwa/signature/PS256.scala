package com.peknight.jose.jwa.signature

import com.peknight.security.digest.{`SHA-256`, `SHA-2`}

object PS256 extends `RSASSA-PSSAlgorithm`:
  def digest: `SHA-2` = `SHA-256`
end PS256
