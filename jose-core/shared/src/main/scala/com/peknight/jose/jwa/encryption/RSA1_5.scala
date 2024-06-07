package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.`Recommended-`
import com.peknight.security.cipher.{RSAES, `RSAES-PKCS1-v1_5`}

object RSA1_5 extends RSAESAlgorithm:
  val encryption: RSAES = `RSAES-PKCS1-v1_5`
  val requirement: Requirement = `Recommended-`
  override val algorithm: String = "RSA1_5"
end RSA1_5
