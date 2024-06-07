package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.jose.jwa.ecc.{Curve, `P-521`}
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-512`}

object ES512 extends ECDSAAlgorithm:
  val curve: Curve = `P-521`
  val digest: MessageDigestAlgorithm = `SHA-512`
  val requirement: Requirement = Optional
end ES512
