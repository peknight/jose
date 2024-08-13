package com.peknight.jose.error.jws

import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwa.signature.ECDSAAlgorithm

case class InvalidECDSAKey(algorithm: ECDSAAlgorithm, curve: Option[Curve]) extends JsonWebSignatureError:
  override def lowPriorityMessage: Option[String] = Some(s"${algorithm.algorithm}/${algorithm.signature.algorithm} expects a key using ${algorithm.curve.name} but was ${curve.fold("none")(_.name)}")
end InvalidECDSAKey
