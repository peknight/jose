package com.peknight.jose.jwe

import com.peknight.jose.jwx.{JoseConfig, JoseHeader, JosePrimitive}

import java.security.Key

case class EncryptionPrimitive(key: Key, recipientHeader: Option[JoseHeader] = None,
                               config: JoseConfig = JoseConfig.default) extends JosePrimitive
