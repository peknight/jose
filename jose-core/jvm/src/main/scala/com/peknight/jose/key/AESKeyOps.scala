package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.security.cipher.AES
import com.peknight.security.crypto.spec.SecretKeySpec
import com.peknight.security.syntax.secureRandom.nextBytesF
import scodec.bits.ByteVector

import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec as JSecretKeySpec

object AESKeyOps:
  def generateKey[F[_]: Sync](keyLengthInBits: Int, random: SecureRandom): F[JSecretKeySpec] =
    random.nextBytesF[F](keyLengthInBits / 8).map(secretKeySpec)

  def secretKeySpec(key: ByteVector): JSecretKeySpec = SecretKeySpec(key, AES)
end AESKeyOps
