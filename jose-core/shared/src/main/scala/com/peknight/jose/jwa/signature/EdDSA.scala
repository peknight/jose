package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional

trait EdDSA extends JWSAlgorithm with com.peknight.security.signature.EdDSA with EdDSAPlatform:
  override def requirement: Requirement = Optional
end EdDSA
object EdDSA extends EdDSA
