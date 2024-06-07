package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.{AESWrap, AESWrap_128}

object A128GCMKW extends AESGCMKWAlgorithm:
  val encryption: AESWrap = AESWrap_128
end A128GCMKW
