package com.peknight.jose.jwk

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.config.CodecConfig
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.derivation.EnumCodecDerivation
import com.peknight.codec.sum.StringType

enum KeyOperationType:
  case
  sign,
  verify,
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
  deriveKey,
  deriveBits
end KeyOperationType
object KeyOperationType:
  val verifyOps: List[KeyOperationType] = List(verify)
  val decryptOps: List[KeyOperationType] = List(decrypt, deriveKey, unwrapKey)
  given stringCodecKeyOperationType[F[_]: Applicative]: Codec[F, String, String, KeyOperationType] =
    EnumCodecDerivation.unsafeDerivedStringCodecEnum[F, KeyOperationType](using CodecConfig.default)
  given codecKeyOperationType[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], KeyOperationType] =
    Codec.codecS[F, S, KeyOperationType]
end KeyOperationType
