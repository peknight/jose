package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwk.KeyType.OctetSequence
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Recommended
import com.peknight.security.cipher.Symmetric

trait DirectEncryptionAlgorithm extends KeyManagementAlgorithm with Symmetric with DirectEncryptionAlgorithmPlatform:
  def algorithm: String = "dir"
  def headerParams: Seq[HeaderParam] = Seq.empty
  def requirement: Requirement = Recommended
  override def keyTypes: List[KeyType] = List(OctetSequence)
  private[jose] def canOverrideCek: Boolean = false
end DirectEncryptionAlgorithm
object DirectEncryptionAlgorithm:
  val values: List[DirectEncryptionAlgorithm] = List(dir)
  given stringCodecDirectEncryptionAlgorithm[F[_]: Applicative]: Codec[F, String, String, DirectEncryptionAlgorithm] =
    stringCodecAlgorithmIdentifier[F, DirectEncryptionAlgorithm](values)
  given codecDirectEncryptionAlgorithm[F[_]: Applicative, S: {StringType, Show}]
  : Codec[F, S, Cursor[S], DirectEncryptionAlgorithm] =
    Codec.codecS[F, S, DirectEncryptionAlgorithm]
end DirectEncryptionAlgorithm
