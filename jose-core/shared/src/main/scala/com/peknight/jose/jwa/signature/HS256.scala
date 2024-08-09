package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.mac.{HmacSHA, HmacSHA256}

object HS256 extends HmacSHAAlgorithm:
  def mac: HmacSHA = HmacSHA256
  val requirement: Requirement = Required
end HS256
