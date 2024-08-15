package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional

trait EdDSA extends com.peknight.security.signature.EdDSA with JWSAlgorithm:
  override def requirement: Requirement = Optional
end EdDSA
object EdDSA extends EdDSA
