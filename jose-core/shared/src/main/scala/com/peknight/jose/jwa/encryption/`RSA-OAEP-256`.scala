package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.cipher.{RSAES, `RSAES-OAEPWithSHA-256AndMGF1Padding`}

object `RSA-OAEP-256` extends RSAESAlgorithm with `RSAES-OAEPWithSHA-256AndMGF1Padding`:
  val encryption: RSAES = `RSAES-OAEPWithSHA-256AndMGF1Padding`
  val requirement: Requirement = Optional
  override val algorithm: String = "RSA-OAEP-256"
end `RSA-OAEP-256`
