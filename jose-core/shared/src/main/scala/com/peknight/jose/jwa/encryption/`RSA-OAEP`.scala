package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.`Recommended+`
import com.peknight.security.cipher.{RSAES, `RSAES-OAEPPadding`}

object `RSA-OAEP` extends RSAESAlgorithm with `RSAES-OAEPPadding`:
  val encryption: RSAES = `RSAES-OAEPPadding`
  val requirement: Requirement = `Recommended+`
  override val algorithm: String = "RSA-OAEP"
end `RSA-OAEP`
