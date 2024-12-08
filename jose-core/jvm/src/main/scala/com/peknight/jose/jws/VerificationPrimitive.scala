package com.peknight.jose.jws

import com.peknight.jose.jwx.{JoseConfiguration, JosePrimitive}

import java.security.Key

case class VerificationPrimitive(key: Option[Key] = None, configuration: JoseConfiguration = JoseConfiguration.default)
  extends JosePrimitive
