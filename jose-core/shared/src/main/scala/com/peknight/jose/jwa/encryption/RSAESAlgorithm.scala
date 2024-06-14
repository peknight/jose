package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.cipher.RSAES

trait RSAESAlgorithm extends KeyEncryptionAlgorithm:
  def encryption: RSAES
  def headerParams: Seq[HeaderParam] = Seq.empty
end RSAESAlgorithm
object RSAESAlgorithm:
  val values: List[RSAESAlgorithm] = RSA1_5 :: `RSA-OAEPAlgorithm`.values
  given stringCodecRSAESAlgorithm[F[_]: Applicative]: Codec[F, String, String, RSAESAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, RSAESAlgorithm](values)
  given codecRSAESAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], RSAESAlgorithm] =
    Codec.codecS[F, S, RSAESAlgorithm]
end RSAESAlgorithm
