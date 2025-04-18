package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier

trait KeyEncryptionAlgorithm extends KeyManagementAlgorithm
object KeyEncryptionAlgorithm:
  val values: List[KeyEncryptionAlgorithm] =
    RSAESAlgorithm.values ::: AESGCMKWAlgorithm.values ::: PBES2Algorithm.values
  given stringCodecKeyEncryptionAlgorithm[F[_]: Applicative]: Codec[F, String, String, KeyEncryptionAlgorithm] =
    stringCodecAlgorithmIdentifier[F, KeyEncryptionAlgorithm](values)
  given codecKeyEncryptionAlgorithm[F[_]: Applicative, S: {StringType, Show}]
  : Codec[F, S, Cursor[S], KeyEncryptionAlgorithm] =
    Codec.codecS[F, S, KeyEncryptionAlgorithm]
end KeyEncryptionAlgorithm
