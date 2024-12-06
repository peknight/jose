package com.peknight.jose.jwe

import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader, JosePrimitive}

import java.security.Key

case class EncryptionPrimitive(key: Key, recipientHeader: Option[JoseHeader] = None,
                               configuration: JoseConfiguration = JoseConfiguration.default)extends JosePrimitive
