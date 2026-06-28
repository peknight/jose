package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwa.encryption.HeaderParam.{apu, apv, epk}
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwk.KeyType.{EllipticCurve, OctetKeyPair}
import com.peknight.security.cipher.Asymmetric

trait `ECDH-ESWithAESWrapAlgorithm` extends KeyAgreementAlgorithm with Asymmetric
  with `ECDH-ESWithAESWrapAlgorithmPlatform`:
  def encryption: AESWrapAlgorithm
  def headerParams: Seq[HeaderParam] = Seq(epk, apu, apv)
  def keyTypes: List[KeyType] = List(EllipticCurve, OctetKeyPair)
  def algorithm: String = s"ECDH-ES+A${encryption.blockSize * 8}KW"
  private[jose] def canOverrideCek: Boolean = encryption.canOverrideCek
end `ECDH-ESWithAESWrapAlgorithm`
object `ECDH-ESWithAESWrapAlgorithm`:
  val values: List[`ECDH-ESWithAESWrapAlgorithm`] = List(`ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`)
  given `stringCodecECDH-ESWithAESWrap`[F[_]: Applicative]
  : Codec[F, String, String, `ECDH-ESWithAESWrapAlgorithm`] =
    stringCodecAlgorithmIdentifier[F, `ECDH-ESWithAESWrapAlgorithm`](values)
  given `codecECDH-ESWithAESWrap`[F[_]: Applicative, S: {StringType, Show}]
  : Codec[F, S, Cursor[S], `ECDH-ESWithAESWrapAlgorithm`] =
    Codec.codecS[F, S, `ECDH-ESWithAESWrapAlgorithm`]
end `ECDH-ESWithAESWrapAlgorithm`
