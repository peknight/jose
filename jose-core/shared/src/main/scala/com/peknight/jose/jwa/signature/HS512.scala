package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.mac.HmacSHA512

object HS512 extends HmacSHA2Algorithm with HmacSHA512:
  val requirement: Requirement = Optional
end HS512
