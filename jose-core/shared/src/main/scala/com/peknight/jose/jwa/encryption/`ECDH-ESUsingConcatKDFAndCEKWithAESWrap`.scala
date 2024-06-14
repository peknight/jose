package com.peknight.jose.jwa.encryption

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.security.cipher.AESWrap

trait `ECDH-ESUsingConcatKDFAndCEKWithAESWrap` extends `ECDH-ESAlgorithm`:
  def encryption: AESWrap
  override def algorithm: String = s"ECDH-ES+A${encryption.blockSize * 8}KW"
end `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`
object `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`:
  val values: List[`ECDH-ESUsingConcatKDFAndCEKWithAESWrap`] = List(`ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`)
  given `stringCodecECDH-ESUsingConcatKDFAndCEKWithAESWrap`[F[_]: Applicative]
  : Codec[F, String, String, `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`] =
    JsonWebAlgorithm.stringCodecAlgorithm[F, `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`](values)
  given `codecECDH-ESUsingConcatKDFAndCEKWithAESWrap`[F[_]: Applicative, S: StringType]
  : Codec[F, S, Cursor[S], `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`] =
    Codec.codecS[F, S, `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`]
end `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`
