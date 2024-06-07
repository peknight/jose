package com.peknight.jose.jwk

import com.peknight.codec.base.Base64Url
import com.peknight.jose.jwk.KeyType.OctetSequence

trait OctetSequenceJsonWebKey extends JsonWebKey:
  def keyType: KeyType = OctetSequence

  /**
   * The "k" (key value) parameter contains the value of the symmetric (or
   * other single-valued) key.  It is represented as the base64url
   * encoding of the octet sequence containing the key value.
   */
  def keyValue: Base64Url
end OctetSequenceJsonWebKey
