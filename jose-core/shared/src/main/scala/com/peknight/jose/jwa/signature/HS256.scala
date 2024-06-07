package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.mac.{HmacSHA2, HmacSHA256}

object HS256 extends HmacSHA2Algorithm:
  def mac: HmacSHA2 = HmacSHA256
  val requirement: Requirement = Required
end HS256
