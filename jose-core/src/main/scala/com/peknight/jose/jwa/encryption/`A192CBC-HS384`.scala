package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.{AES, AES_192}
import com.peknight.security.mac.{HmacSHA2, HmacSHA384}
import com.peknight.security.oid.ObjectIdentifier

object `A192CBC-HS384` extends AESCBCHmacSHA2Algorithm:
  val encryption: AES = AES_192 / CBC
  val mac: HmacSHA2 = HmacSHA384
  val requirement: Requirement = Optional
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.22"))
end `A192CBC-HS384`
