package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.mac.HmacSHA512

object HS512 extends HmacSHA with HmacSHA512:
  val requirement: Requirement = Optional
end HS512
