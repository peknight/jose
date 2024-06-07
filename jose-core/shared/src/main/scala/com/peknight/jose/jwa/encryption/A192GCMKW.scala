package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.{AESWrap, AESWrap_192}

object A192GCMKW extends AESGCMKWAlgorithm:
  val encryption: AESWrap = AESWrap_192
end A192GCMKW
