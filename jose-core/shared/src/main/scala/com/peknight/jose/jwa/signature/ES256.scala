package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.`Recommended+`
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-256`}
import com.peknight.security.ecc.sec.secp256r1
import com.peknight.security.spec.ECGenParameterSpecName

object ES256 extends ECDSAAlgorithm:
  val curveName: ECGenParameterSpecName = secp256r1
  override val digest: MessageDigestAlgorithm = `SHA-256`
  val requirement: Requirement = `Recommended+`
end ES256
