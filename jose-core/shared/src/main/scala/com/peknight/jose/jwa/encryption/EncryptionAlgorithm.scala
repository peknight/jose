package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.Requirement
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.algorithm.Algorithm

trait EncryptionAlgorithm extends Algorithm:
  def requirement: Requirement
end EncryptionAlgorithm
object EncryptionAlgorithm:
  val values: List[EncryptionAlgorithm] = JWEEncryptionAlgorithm.values
  given stringCodecEncryptionAlgorithm[F[_]: Applicative]: Codec[F, String, String, EncryptionAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, EncryptionAlgorithm](values)
  given codecEncryptionAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], EncryptionAlgorithm] =
    Codec.codecS[F, S, EncryptionAlgorithm]
end EncryptionAlgorithm
