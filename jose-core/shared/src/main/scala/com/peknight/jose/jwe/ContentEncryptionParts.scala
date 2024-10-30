package com.peknight.jose.jwe

import scodec.bits.ByteVector

case class ContentEncryptionParts(iv: ByteVector, ciphertext: ByteVector, authenticationTag: ByteVector)
