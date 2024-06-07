package com.peknight.jose.jwa.signature

import com.peknight.security.signature.`RSASSA-PKCS1-v1_5`
import com.peknight.security.digest.`SHA-2`

trait `RSASSA-PKCS1-v1_5Algorithm` extends JWSAlgorithm with `RSASSA-PKCS1-v1_5`:
  def digest: `SHA-2`
  override def algorithm: String = s"RS${digest.bitLength}"
end `RSASSA-PKCS1-v1_5Algorithm`
