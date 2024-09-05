package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.cipher.AESWrap

trait AESWrapAlgorithm extends KeyWrappingAlgorithm with AESWrap with AESWrapAlgorithmPlatform:
  def headerParams: Seq[HeaderParam] = Seq.empty
  override def identifier: String = s"A${blockSize * 8}KW"
end AESWrapAlgorithm
object AESWrapAlgorithm:
  val values: List[AESWrapAlgorithm] = List(A128KW, A192KW, A256KW)
  given stringCodecAESWrapAlgorithm[F[_]: Applicative]: Codec[F, String, String, AESWrapAlgorithm] =
    stringCodecAlgorithmIdentifier[F, AESWrapAlgorithm](values)
  given codecAESWrapAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], AESWrapAlgorithm] =
    Codec.codecS[F, S, AESWrapAlgorithm]
end AESWrapAlgorithm
