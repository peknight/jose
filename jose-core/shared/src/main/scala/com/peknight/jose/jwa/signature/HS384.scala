package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.mac.{HmacSHA, HmacSHA384}

object HS384 extends HmacSHAAlgorithm:
  def mac: HmacSHA = HmacSHA384
  val requirement: Requirement = Optional
end HS384
