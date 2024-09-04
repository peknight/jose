package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.padding.NoPadding
import scodec.bits.ByteVector
import java.security.Key

trait AESGCMKWAlgorithmPlatform { self: AESGCMKWAlgorithm =>
  private val javaAlgorithm: AES = AES / GCM / NoPadding
  private val ivByteLength = 12
  private val tagByteLength = 16
  def encryptKey[F[_]: Sync](key: Key): F[ByteVector] = ???
}
