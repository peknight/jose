package com.peknight.jose.jwk

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.{Optional, Required, `Recommended+`}

enum KeyType(val name: String, val requirement: Requirement) derives CanEqual:
  case EllipticCurve extends KeyType("EC", `Recommended+`)
  case RSA extends KeyType("RSA", Required)
  case OctetSequence extends KeyType("oct", Required)
  case OctetKeyPair extends KeyType("OKP", Optional)
end KeyType
object KeyType:
  given stringCodecKeyType[F[_]: Applicative]: Codec[F, String, String, KeyType] =
    Codec.mapOption[F, String, String, KeyType](_.name)(name => KeyType.values.find(_.name == name))
  given codecKeyType[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], KeyType] =
    Codec.codecS[F, S, KeyType]
end KeyType
