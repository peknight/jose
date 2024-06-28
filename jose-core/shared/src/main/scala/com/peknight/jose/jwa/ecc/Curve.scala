package com.peknight.jose.jwa.ecc

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import com.peknight.codec.sum.StringType
import com.peknight.security.error.UnknownAlgorithm
import com.peknight.security.oid.ObjectIdentifier
import com.peknight.security.spec.ECGenParameterSpecName

trait Curve:
  def std: ECGenParameterSpecName
  def name: String
  def oid: Option[ObjectIdentifier] = std.oid
end Curve
object Curve extends CurvePlatform:
  val values: List[Curve] = List(`P-256`, `P-256K`, `P-384`, `P-521`, prime256v1)
  given stringCodecCurve[F[_]: Applicative]: Codec[F, String, String, Curve] =
    Codec.applicative[F, String, String, Curve](_.name)(
      name => values.find(_.name == name).toRight(DecodingFailure(UnknownAlgorithm(name)))
    )
  given codecCurve[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], Curve] =
    Codec.codecS[F, S, Curve]
end Curve
