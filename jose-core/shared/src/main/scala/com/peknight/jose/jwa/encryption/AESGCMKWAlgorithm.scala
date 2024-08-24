package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.encryption.HeaderParam.{iv, tag}
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.AESWrap

trait AESGCMKWAlgorithm extends KeyEncryptionAlgorithm:
  def encryption: AESWrap
  def headerParams: Seq[HeaderParam] = Seq(iv, tag)
  def requirement: Requirement = Optional
  def algorithm: String = s"A${encryption.blockSize * 8}GCMKW"
end AESGCMKWAlgorithm
object AESGCMKWAlgorithm:
  val values: List[AESGCMKWAlgorithm] = List(A128GCMKW, A192GCMKW, A256GCMKW)
  given stringCodecAESGCMKWAlgorithm[F[_]: Applicative]: Codec[F, String, String, AESGCMKWAlgorithm] =
    stringCodecAlgorithmIdentifier[F, AESGCMKWAlgorithm](values)
  given codecAESGCMKWAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESGCMKWAlgorithm] =
    Codec.codecS[F, S, AESGCMKWAlgorithm]
end AESGCMKWAlgorithm
