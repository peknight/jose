package com.peknight.jose.error.jwk

import java.security.PublicKey
import java.security.cert.X509Certificate

case class BareKeyCertMismatch(publicKey: PublicKey, leafCertificate: X509Certificate) extends JsonWebKeyError:
  override def lowPriorityMessage: Option[String] =
    Some(s"The key in the first certificate MUST match the bare public key represented by other members of the JWK. Public key = $publicKey, cert = $leafCertificate")
end BareKeyCertMismatch
