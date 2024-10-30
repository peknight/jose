package com.peknight.jose.jwe

import com.peknight.jose.jwk.JsonWebKey
import scodec.bits.ByteVector

case class ContentEncryptionKeys(contentEncryptionKey: ByteVector,
                                 encryptedKey: Option[ByteVector] = None,
                                 ephemeralPublicKey: Option[JsonWebKey] = None,
                                 iv: Option[ByteVector] = None,
                                 authenticationTag: Option[ByteVector] = None
                                )
