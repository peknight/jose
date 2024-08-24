package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Required
import com.peknight.security.mac.HmacSHA256

object HS256 extends HmacSHAAlgorithm with HmacSHA256:
  val requirement: Requirement = Required
end HS256
