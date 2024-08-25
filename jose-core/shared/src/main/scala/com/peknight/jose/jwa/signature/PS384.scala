package com.peknight.jose.jwa.signature

import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-384`}

object PS384 extends `RSASSA-PSS`:
  def digest: MessageDigestAlgorithm = `SHA-384`
end PS384
