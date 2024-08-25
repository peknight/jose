package com.peknight.jose.jwa.signature

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.jose.jwa.AlgorithmIdentifier.stringCodecAlgorithmIdentifier
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.RSA
import com.peknight.security.digest.`SHA-2`
import com.peknight.security.mgf.{MGF, MGF1}
import com.peknight.security.oid.ObjectIdentifier

trait `RSASSA-PSS` extends RSASSA with com.peknight.security.signature.`RSASSA-PSS` with `RSASSA-PSSPlatform`:
  def requirement: Requirement = Optional
  override def identifier: String = s"PS${digest.bitLength}"
end `RSASSA-PSS`
object `RSASSA-PSS`:
  val values: List[`RSASSA-PSS`] = List(PS256, PS384, PS512)
  given `stringCodecRSASSA-PSS`[F[_]: Applicative]: Codec[F, String, String, `RSASSA-PSS`] =
    stringCodecAlgorithmIdentifier[F, `RSASSA-PSS`](values)
  given `codecRSASSA-PSS`[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], `RSASSA-PSS`] =
    Codec.codecS[F, S, `RSASSA-PSS`]
end `RSASSA-PSS`
