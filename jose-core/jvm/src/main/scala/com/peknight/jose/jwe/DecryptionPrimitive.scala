package com.peknight.jose.jwe

import com.peknight.jose.jwx.JoseConfiguration

import java.security.Key

case class DecryptionPrimitive(key: Key, configuration: JoseConfiguration = JoseConfiguration.default)
