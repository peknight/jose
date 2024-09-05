package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier

trait JWEEncryptionAlgorithm extends EncryptionAlgorithm with JWEEncryptionAlgorithmPlatform:
  def keyByteLength: Int
end JWEEncryptionAlgorithm
object JWEEncryptionAlgorithm:
  val values: List[JWEEncryptionAlgorithm] = AESCBCHmacSHA2Algorithm.values ::: AESGCMAlgorithm.values
  given stringCodecJWEEncryptionAlgorithm[F[_]: Applicative]: Codec[F, String, String, JWEEncryptionAlgorithm] =
    stringCodecAlgorithmIdentifier[F, JWEEncryptionAlgorithm](values)
  given codecJWEEncryptionAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], JWEEncryptionAlgorithm] =
    Codec.codecS[F, S, JWEEncryptionAlgorithm]
end JWEEncryptionAlgorithm
