package com.peknight.jose.jwa.signature

import com.peknight.security.digest.`SHA-2`

trait `RSASSA-PKCS1-v1_5Algorithm` extends JWSAlgorithm:
  def digest: `SHA-2`
  def algorithm: String = s"RS${digest.bitLength}"
end `RSASSA-PKCS1-v1_5Algorithm`
