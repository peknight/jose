package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.encryption.HeaderParam.{iv, tag}
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwk.KeyType.OctetSequence
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.mode.{CipherAlgorithmMode, GCM}
import com.peknight.security.cipher.{AES, AESWrap}

trait AESGCMKWAlgorithm extends KeyEncryptionAlgorithm with AESWrap with AESGCMKWAlgorithmPlatform:
  def ivByteLength = 12
  def tagByteLength = 16
  def headerParams: Seq[HeaderParam] = Seq(iv, tag)
  def requirement: Requirement = Optional
  def keyType: Option[KeyType] = Some(OctetSequence)
  private[jose] def canOverrideCek: Boolean = true
  override def algorithm: String = AES.algorithm
  override def mode: CipherAlgorithmMode = GCM
  override def identifier: String = s"A${blockSize * 8}GCMKW"
end AESGCMKWAlgorithm
object AESGCMKWAlgorithm:
  val values: List[AESGCMKWAlgorithm] = List(A128GCMKW, A192GCMKW, A256GCMKW)
  given stringCodecAESGCMKWAlgorithm[F[_]: Applicative]: Codec[F, String, String, AESGCMKWAlgorithm] =
    stringCodecAlgorithmIdentifier[F, AESGCMKWAlgorithm](values)
  given codecAESGCMKWAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESGCMKWAlgorithm] =
    Codec.codecS[F, S, AESGCMKWAlgorithm]
end AESGCMKWAlgorithm
