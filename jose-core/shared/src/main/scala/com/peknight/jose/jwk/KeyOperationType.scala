package com.peknight.jose.jwk

enum KeyOperationType(val entryName: String):
  case Sign extends KeyOperationType("sign")
  case Verify extends KeyOperationType("verify")
  case Encrypt extends KeyOperationType("encrypt")
  case Decrypt extends KeyOperationType("decrypt")
  case WrapKey extends KeyOperationType("wrapKey")
  case UnwrapKey extends KeyOperationType("unwrapKey")
  case DeriveKey extends KeyOperationType("deriveKey")
  case DeriveBits extends KeyOperationType("deriveBits")
end KeyOperationType