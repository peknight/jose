package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.cipher.AES
import com.peknight.security.mac.HmacSHA2

trait AESCBCHmacSHA2Algorithm extends JWEEncryptionAlgorithm:
  def encryption: AES
  def mac: HmacSHA2
  def algorithm: String = s"A${encryption.blockSize * 8}CBC-HS${mac.digest.bitLength}"
end AESCBCHmacSHA2Algorithm
object AESCBCHmacSHA2Algorithm:
  val values: List[AESCBCHmacSHA2Algorithm] = List(`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`)
  given stringCodecAESCBCHmacSHA2Algorithm[F[_]: Applicative]: Codec[F, String, String, AESCBCHmacSHA2Algorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, AESCBCHmacSHA2Algorithm](values)
  given codecAESCBCHmacSHA2Algorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESCBCHmacSHA2Algorithm] =
    Codec.codecS[F, S, AESCBCHmacSHA2Algorithm]
end AESCBCHmacSHA2Algorithm
