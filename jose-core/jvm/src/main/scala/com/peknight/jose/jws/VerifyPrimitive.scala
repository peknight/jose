package com.peknight.jose.jws

import com.peknight.jose.jwx.JoseContext

import java.security.Key

case class VerifyPrimitive(key: Option[Key] = None, context: JoseContext = JoseContext.default)
