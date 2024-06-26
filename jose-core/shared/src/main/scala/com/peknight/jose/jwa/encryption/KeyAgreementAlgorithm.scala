package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm

trait KeyAgreementAlgorithm extends KeyManagementAlgorithm
object KeyAgreementAlgorithm:
  val values: List[KeyAgreementAlgorithm] = `ECDH-ESAlgorithm`.values
  given stringCodecKeyAgreementAlgorithm[F[_]: Applicative]: Codec[F, String, String, KeyAgreementAlgorithm] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, KeyAgreementAlgorithm](values)
  given codecKeyAgreementAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], KeyAgreementAlgorithm] =
    Codec.codecS[F, S, KeyAgreementAlgorithm]
end KeyAgreementAlgorithm
