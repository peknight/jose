package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.cipher.mode.CipherAlgorithmMode
import com.peknight.security.cipher.padding.CipherAlgorithmPadding
import com.peknight.security.cipher.{AEAD, AES}
import com.peknight.security.mac.HmacSHA2

trait AESHmacSHA2Algorithm extends JWEEncryptionAlgorithm with AEAD with AESHmacSHA2AlgorithmPlatform:
  type This = AEAD
  def encryption: AES
  def mac: HmacSHA2
  def keyByteLength: Int = encryption.blockSize / 4
  def tagTruncationLength: Int = encryption.blockSize / 8
  override def identifier: String = s"A${encryption.blockSize * 8}${encryption.mode.mode}-HS${mac.digest.bitLength}"
  override def /(mode: CipherAlgorithmMode): AEAD =
    if mode == encryption.mode then this else AEAD(encryption / mode, mac)
  override def /(padding: CipherAlgorithmPadding): AEAD =
    if padding == encryption.padding then this else AEAD(encryption / padding, mac)
end AESHmacSHA2Algorithm
object AESHmacSHA2Algorithm:
  val values: List[AESHmacSHA2Algorithm] = List(`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`)
  given stringCodecAESCBCHmacSHA2Algorithm[F[_]: Applicative]: Codec[F, String, String, AESHmacSHA2Algorithm] =
    stringCodecAlgorithmIdentifier[F, AESHmacSHA2Algorithm](values)
  given codecAESCBCHmacSHA2Algorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESHmacSHA2Algorithm] =
    Codec.codecS[F, S, AESHmacSHA2Algorithm]
end AESHmacSHA2Algorithm
