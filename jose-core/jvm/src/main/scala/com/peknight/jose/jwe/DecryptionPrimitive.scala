package com.peknight.jose.jwe

import com.peknight.jose.jwx.JoseConfiguration

import java.security.Key

case class DecryptionPrimitive(managementKey: Key, configuration: JoseConfiguration = JoseConfiguration.default)
