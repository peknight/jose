package com.peknight.jose.jwe

import com.peknight.jose.jwk.JsonWebKey
import scodec.bits.ByteVector

case class ContentEncryptionKeys(contentEncryptionKey: ByteVector,
                                 encryptedKey: ByteVector,
                                 ephemeralPublicKey: Option[JsonWebKey] = None,
                                 initializationVector: Option[ByteVector] = None,
                                 authenticationTag: Option[ByteVector] = None,
                                 pbes2SaltInput: Option[ByteVector] = None,
                                 pbes2Count: Option[Long] = None
                                )
