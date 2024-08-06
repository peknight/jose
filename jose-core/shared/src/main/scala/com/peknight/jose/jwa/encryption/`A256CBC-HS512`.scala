package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.{AES, AES_192, AES_256}
import com.peknight.security.mac.{HmacSHA2, HmacSHA512}
import com.peknight.security.oid.ObjectIdentifier

object `A256CBC-HS512` extends AESHmacSHA2Algorithm:
  val encryption: AES = AES_256 / CBC
  val mac: HmacSHA2 = HmacSHA512
  val requirement: Requirement = Required
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.42"))
end `A256CBC-HS512`
