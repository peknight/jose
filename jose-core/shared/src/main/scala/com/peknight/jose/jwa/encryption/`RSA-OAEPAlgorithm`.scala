package com.peknight.jose.jwa.encryption

import cats.{Applicative, Show}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.security.oid.ObjectIdentifier

trait `RSA-OAEPAlgorithm` extends RSAESAlgorithm:
  override def oid: Option[ObjectIdentifier] = Some(ObjectIdentifier.unsafeFromString("1.2.840.113549.1.1.7"))
end `RSA-OAEPAlgorithm`
object `RSA-OAEPAlgorithm`:
  val values: List[`RSA-OAEPAlgorithm`] = List(`RSA-OAEP`, `RSA-OAEP-256`)
  given `stringCodecRSA-OAEPAlgorithm`[F[_]: Applicative]: Codec[F, String, String, `RSA-OAEPAlgorithm`] =
    stringCodecAlgorithmIdentifier[F, `RSA-OAEPAlgorithm`](values)
  given `codecRSA-OAEPAlgorithm`[F[_]: Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], `RSA-OAEPAlgorithm`] =
    Codec.codecS[F, S, `RSA-OAEPAlgorithm`]
end `RSA-OAEPAlgorithm`
