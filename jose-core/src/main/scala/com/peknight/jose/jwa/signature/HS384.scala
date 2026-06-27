package com.peknight.jose.jwa.signature

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.mac.HmacSHA384

object HS384 extends HmacSHA with HmacSHA384:
  val requirement: Requirement = Optional
end HS384
