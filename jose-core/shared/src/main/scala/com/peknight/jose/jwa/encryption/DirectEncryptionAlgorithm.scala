package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.jose.jwa.JsonWebAlgorithm

trait DirectEncryptionAlgorithm extends KeyManagementAlgorithm:
  def algorithm: String = "dir"
  def headerParams: Seq[HeaderParam] = Seq.empty
  def requirement: Requirement = Recommended
end DirectEncryptionAlgorithm
object DirectEncryptionAlgorithm:
  val values: List[DirectEncryptionAlgorithm] = List(dir)
  given stringCodecDirectEncryptionAlgorithm[F[_]: Applicative]: Codec[F, String, String, DirectEncryptionAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, DirectEncryptionAlgorithm](values)
  given codecDirectEncryptionAlgorithm[F[_]: Applicative, S: StringType]
  : Codec[F, S, Cursor[S], DirectEncryptionAlgorithm] =
    Codec.codecS[F, S, DirectEncryptionAlgorithm]
end DirectEncryptionAlgorithm
