package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.{AESWrap, AESWrap_256}

object A256GCMKW extends AESGCMKWAlgorithm:
  val encryption: AESWrap = AESWrap_256
end A256GCMKW
