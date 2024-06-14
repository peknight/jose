package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.{AES, AES_128}
import com.peknight.security.mac.{HmacSHA2, HmacSHA256}
import com.peknight.security.oid.ObjectIdentifier

object `A128CBC-HS256` extends AESCBCHmacSHA2Algorithm with AES_128:
  val encryption: AES = AES_128 / CBC
  val mac: HmacSHA2 = HmacSHA256
  val requirement: Requirement = Required
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("2.16.840.1.101.3.4.1.2"))
end `A128CBC-HS256`
