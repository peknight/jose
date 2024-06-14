package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.encryption.HeaderParam.{apu, apv, epk}

trait `ECDH-ESAlgorithm` extends KeyAgreementAlgorithm:
  def headerParams: Seq[HeaderParam] = Seq(epk, apu, apv)
end `ECDH-ESAlgorithm`
object `ECDH-ESAlgorithm`:
  val values: List[`ECDH-ESAlgorithm`] = `ECDH-ES` :: `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`.values
  given `stringCodecECDH-ESAlgorithm`[F[_]: Applicative]: Codec[F, String, String, `ECDH-ESAlgorithm`] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, `ECDH-ESAlgorithm`](values)

  given `codecECDH-ESAlgorithm`[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], `ECDH-ESAlgorithm`] =
    Codec.codecS[F, S, `ECDH-ESAlgorithm`]
end `ECDH-ESAlgorithm`
