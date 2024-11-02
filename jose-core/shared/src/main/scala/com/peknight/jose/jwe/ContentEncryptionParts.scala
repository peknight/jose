package com.peknight.jose.jwe

import scodec.bits.ByteVector

case class ContentEncryptionParts(initializationVector: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector)
