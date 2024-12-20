package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional

trait EdDSA extends JWSAlgorithm with com.peknight.security.signature.EdDSA with EdDSAPlatform:
  override def requirement: Requirement = Optional
  def keyTypes: List[KeyType] = List(KeyType.OctetKeyPair)
end EdDSA
object EdDSA extends EdDSA:
  val values: List[EdDSA] = List(EdDSA)
  given stringCodecEdDSA[F[_]: Applicative]: Codec[F, String, String, EdDSA] =
    stringCodecAlgorithmIdentifier[F, EdDSA](values)
  given codecEdDSA[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], EdDSA] =
    Codec.codecS[F, S, EdDSA]
end EdDSA
