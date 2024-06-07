package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.mac.{HmacSHA2, HmacSHA384}

object HS384 extends HmacSHA2Algorithm:
  def mac: HmacSHA2 = HmacSHA384
  val requirement: Requirement = Optional
end HS384
