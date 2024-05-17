package com.peknight.jose.jwk

enum KeyOperationType:
  case
  sign,
  verify,
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
  deriveKey,
  deriveBits
end KeyOperationType