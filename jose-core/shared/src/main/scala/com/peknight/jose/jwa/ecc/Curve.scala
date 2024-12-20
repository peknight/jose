package com.peknight.jose.jwa.ecc

import cats.{Applicative, Eq}
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import com.peknight.codec.sum.StringType
import com.peknight.security.error.UnknownAlgorithm
import com.peknight.security.spec.ECGenParameterSpecName

trait Curve extends ECGenParameterSpecName derives CanEqual:
  def name: String
  override def toString: String = name
end Curve
object Curve extends CurveCompanion:
  given Eq[Curve] = Eq.fromUniversalEquals[Curve]
  given stringCodecCurve[F[_]: Applicative]: Codec[F, String, String, Curve] =
    Codec.applicative[F, String, String, Curve](_.name)(
      name => values
        .find(curve => curve.name == name || curve.parameterSpecName == name)
        .orElse(if prime256v1.name == name then Some(prime256v1) else None)
        .toRight(DecodingFailure(UnknownAlgorithm(name)))
    )
  given codecCurve[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], Curve] =
    Codec.codecS[F, S, Curve]
end Curve
