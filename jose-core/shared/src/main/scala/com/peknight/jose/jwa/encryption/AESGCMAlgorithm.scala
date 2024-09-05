package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.{CipherAlgorithmMode, GCM}

trait AESGCMAlgorithm extends JWEEncryptionAlgorithm with AES with AESGCMAlgorithmPlatform:
  def keyByteLength: Int = blockSize
  def ivByteLength: Int = 12
  def tagByteLength: Int = 16
  override def algorithm: String = AES.algorithm
  override def mode: CipherAlgorithmMode = GCM
  override def identifier: String = s"A${blockSize * 8}GCM"
end AESGCMAlgorithm
object AESGCMAlgorithm:
  val values: List[AESGCMAlgorithm] = List(A128GCM, A192GCM, A256GCM)
  given stringCodecAESGCMAlgorithm[F[_]: Applicative]: Codec[F, String, String, AESGCMAlgorithm] =
    stringCodecAlgorithmIdentifier[F, AESGCMAlgorithm](values)
  given codecAESGCMAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESGCMAlgorithm] =
    Codec.codecS[F, S, AESGCMAlgorithm]
end AESGCMAlgorithm
