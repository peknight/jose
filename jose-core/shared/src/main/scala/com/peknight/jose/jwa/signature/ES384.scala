package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-384`}
import com.peknight.security.ecc.sec.secp384r1
import com.peknight.security.spec.ECGenParameterSpecName

object ES384 extends ECDSAAlgorithm:
  val curveName: ECGenParameterSpecName = secp384r1
  override val digest: MessageDigestAlgorithm = `SHA-384`
  val requirement: Requirement = Optional
end ES384
