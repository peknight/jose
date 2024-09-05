package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.padding.{CipherAlgorithmPadding, `OAEPWithSHA-256AndMGF1Padding`}
import com.peknight.security.cipher.`RSAES-OAEPWithSHA-256AndMGF1Padding`

object `RSA-OAEP-256` extends `RSA-OAEPAlgorithm` with `RSAES-OAEPWithSHA-256AndMGF1Padding`:
  override def padding: CipherAlgorithmPadding = `OAEPWithSHA-256AndMGF1Padding`
  val requirement: Requirement = Optional
  override val identifier: String = "RSA-OAEP-256"
end `RSA-OAEP-256`
