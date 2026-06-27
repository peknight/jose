package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.`Recommended+`
import com.peknight.security.cipher.padding.{CipherAlgorithmPadding, OAEP}
import com.peknight.security.cipher.`RSAES-OAEPPadding`
import com.peknight.security.digest.`SHA-1`
import com.peknight.security.mgf.MGF1

object `RSA-OAEP` extends `RSA-OAEPAlgorithm` with `RSAES-OAEPPadding`:
  override def padding: CipherAlgorithmPadding = OAEP.withDigestAndMGF(`SHA-1`, MGF1)
  val requirement: Requirement = `Recommended+`
  override val identifier: String = "RSA-OAEP"
end `RSA-OAEP`
