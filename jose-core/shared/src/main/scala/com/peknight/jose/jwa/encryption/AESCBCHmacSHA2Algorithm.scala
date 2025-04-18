package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.cipher.mode.{CBC, CipherAlgorithmMode}
import com.peknight.security.cipher.padding.{CipherAlgorithmPadding, PKCS5Padding}
import com.peknight.security.cipher.{AEAD, AES, Symmetric}
import com.peknight.security.mac.HmacSHA2
import com.peknight.security.spec.SecretKeySpecAlgorithm

trait AESCBCHmacSHA2Algorithm extends EncryptionAlgorithm with AEAD with Symmetric with AESCBCHmacSHA2AlgorithmPlatform:
  type This = AEAD
  def encryption: AES
  def mac: HmacSHA2
  def cekByteLength: Int = encryption.blockSize * 2
  def tagTruncationLength: Int = encryption.blockSize
  def ivByteLength: Int = 16
  def javaAlgorithm: AES = AES / CBC / PKCS5Padding
  def cekAlgorithm: SecretKeySpecAlgorithm = javaAlgorithm
  override def identifier: String = s"A${encryption.blockSize * 8}${encryption.mode.mode}-HS${mac.digest.bitLength}"
  override def /(mode: CipherAlgorithmMode): AEAD =
    if mode == encryption.mode then this else AEAD(encryption / mode, mac)
  override def /(padding: CipherAlgorithmPadding): AEAD =
    if padding == encryption.padding then this else AEAD(encryption / padding, mac)
end AESCBCHmacSHA2Algorithm
object AESCBCHmacSHA2Algorithm:
  val values: List[AESCBCHmacSHA2Algorithm] = List(`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`)
  given stringCodecAESCBCHmacSHA2Algorithm[F[_]: Applicative]: Codec[F, String, String, AESCBCHmacSHA2Algorithm] =
    stringCodecAlgorithmIdentifier[F, AESCBCHmacSHA2Algorithm](values)
  given codecAESCBCHmacSHA2Algorithm[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], AESCBCHmacSHA2Algorithm] =
    Codec.codecS[F, S, AESCBCHmacSHA2Algorithm]
end AESCBCHmacSHA2Algorithm
