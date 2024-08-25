package com.peknight.jose.jwa.signature

import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-256`}

object PS256 extends `RSASSA-PSS`:
  def digest: MessageDigestAlgorithm = `SHA-256`
end PS256
