package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.jose.jwa.ecc.{Curve, `P-384`}
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-384`}

object ES384 extends ECDSAAlgorithm:
  val curve: Curve = `P-384`
  val digest: MessageDigestAlgorithm = `SHA-384`
  val requirement: Requirement = Optional
end ES384
