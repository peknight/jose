package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-512`}
import com.peknight.security.ecc.sec.secp521r1
import com.peknight.security.spec.ECGenParameterSpecName

object ES512 extends ECDSAAlgorithm:
  val curveName: ECGenParameterSpecName = secp521r1
  override val digest: MessageDigestAlgorithm = `SHA-512`
  val requirement: Requirement = Optional
end ES512
