package com.peknight.jose.jws.ops

import cats.effect.kernel.Sync
import cats.syntax.functor.*
import com.peknight.jose.jwa.signature.`RSASSA-PSSAlgorithm`
import com.peknight.security.Security
import com.peknight.security.signature.{Signature, SignatureAlgorithm, `RSASSA-PSS`}

object `RSASSA-PSSOps`:
  def getSignatureAlgorithm[F[_]: Sync](algorithm: `RSASSA-PSSAlgorithm`, useLegacyName: Boolean): F[SignatureAlgorithm] =
    Security.getAlgorithms[F](Signature).map(algorithms =>
      if algorithms.contains(`RSASSA-PSS`.algorithm) && useLegacyName then `RSASSA-PSS` else algorithm.signature
    )

end `RSASSA-PSSOps`
