package com.peknight.jose.jwa.encryption

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.GCM
import com.peknight.security.cipher.padding.NoPadding
import com.peknight.security.provider.Provider
import com.peknight.security.spec.GCMParameterSpec
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait AESGCMKWAlgorithmPlatform { self: AESGCMKWAlgorithm =>
  private val javaAlgorithm: AES = AES / GCM / NoPadding
  private val ivByteLength = 12
  private val tagByteLength = 16
  def encryptKey[F[_]: Sync](key: Key, keyByteLength: Int, cekOverride: Option[ByteVector] = None,
                             ivOverride: Option[ByteVector] = None, random: Option[SecureRandom] = None,
                             provider: Option[Provider | JProvider] = None)
  : F[(ByteVector, ByteVector, ByteVector, ByteVector)] =
    for
      cek <- getBytesOrRandom[F](keyByteLength, cekOverride, random)
      iv <- getBytesOrRandom[F](ivByteLength, ivOverride, random)
      encrypted <- javaAlgorithm.keyEncrypt[F](key, cek, Some(GCMParameterSpec(tagByteLength * 8, iv)), provider = provider)
    yield
      val (encryptedKey, authenticationTag) = encrypted.splitAt(encrypted.length - tagByteLength)
      (cek, iv, encryptedKey, authenticationTag)

}
