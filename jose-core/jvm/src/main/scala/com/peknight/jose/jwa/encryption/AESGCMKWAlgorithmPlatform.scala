package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.padding.NoPadding


trait AESGCMKWAlgorithmPlatform { self: AESGCMKWAlgorithm =>
  private val javaAlgorithm: AES = AES / GCM / NoPadding
  private val ivByteLength = 12
  private val tagByteLength = 16
}
