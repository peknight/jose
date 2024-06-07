package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.mac.HmacSHA256

object HS256 extends HmacSHA2Algorithm with HmacSHA256:
  val requirement: Requirement = Required
end HS256
