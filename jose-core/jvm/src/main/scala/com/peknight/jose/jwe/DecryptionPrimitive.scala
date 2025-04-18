package com.peknight.jose.jwe

import cats.Applicative
import cats.data.NonEmptyList
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.error.collection.CollectionEmpty
import com.peknight.jose.jwx.{JoseConfig, JosePrimitive}

import java.security.Key

case class DecryptionPrimitive(key: Key, config: JoseConfig = JoseConfig.default)
  extends JosePrimitive
object DecryptionPrimitive:
  def decryptionKey[F[_]: Applicative](key: Key)
  : (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]] =
    (_, config) => NonEmptyList.one(DecryptionPrimitive(key, config)).asRight[Error].pure[F]
  def defaultDecryptionPrimitivesF[F[_]: Applicative]
  : (JsonWebEncryption, JoseConfig) => F[Either[Error, NonEmptyList[DecryptionPrimitive]]] =
    (_, _) => CollectionEmpty.label("primitives").asLeft[NonEmptyList[DecryptionPrimitive]].pure[F]
end DecryptionPrimitive
