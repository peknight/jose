package com.peknight.jose.jwk

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType

enum PublicKeyUseType(val entryName: String) derives CanEqual:
  case Signature extends PublicKeyUseType("sig")
  case Encryption extends PublicKeyUseType("enc")
end PublicKeyUseType
object PublicKeyUseType:
  given stringCodecPublicKeyUseType[F[_]: Applicative]: Codec[F, String, String, PublicKeyUseType] =
    Codec.mapOption[F, String, String, PublicKeyUseType](_.entryName)(
      entryName => PublicKeyUseType.values.find(_.entryName == entryName)
    )
  given codecPublicKeyUseType[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], PublicKeyUseType] =
    Codec.codecS[F, S, PublicKeyUseType]
end PublicKeyUseType
