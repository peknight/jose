package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.cipher.AES

trait AESGCMAlgorithm extends JWEEncryptionAlgorithm:
  def encryption: AES
  def algorithm: String = s"A${encryption.blockSize * 8}GCM"
end AESGCMAlgorithm
object AESGCMAlgorithm:
  val values: List[AESGCMAlgorithm] = List(A128GCM, A192GCM, A256GCM)
  given stringCodecAESGCMAlgorithm[F[_]: Applicative]: Codec[F, String, String, AESGCMAlgorithm] =
    stringCodecAlgorithmIdentifier[F, AESGCMAlgorithm](values)
  given codecAESGCMAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESGCMAlgorithm] =
    Codec.codecS[F, S, AESGCMAlgorithm]
end AESGCMAlgorithm
