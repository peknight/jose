package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwx.Requirement
import com.peknight.security.spec.SecretKeySpecAlgorithm

trait EncryptionAlgorithm extends AlgorithmIdentifier with EncryptionAlgorithmPlatform:
  def cekByteLength: Int
  def cekAlgorithm: SecretKeySpecAlgorithm
  def requirement: Requirement
end EncryptionAlgorithm
object EncryptionAlgorithm:
  val values: List[EncryptionAlgorithm] = AESCBCHmacSHA2Algorithm.values ::: AESGCMAlgorithm.values
  given stringCodecEncryptionAlgorithm[F[_]: Applicative]: Codec[F, String, String, EncryptionAlgorithm] =
    stringCodecAlgorithmIdentifier[F, EncryptionAlgorithm](values)
  given codecEncryptionAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], EncryptionAlgorithm] =
    Codec.codecS[F, S, EncryptionAlgorithm]
end EncryptionAlgorithm
