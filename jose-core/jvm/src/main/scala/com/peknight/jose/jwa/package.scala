package com.peknight.jose

import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.validation.spire.math.interval.either.atOrAbove

import java.security.interfaces.RSAKey

package object jwa:
  def checkRSAKeySize(key: RSAKey): Either[Error, Unit] =
    Option(key.getModulus)
      .flatMap(modulus => Option(modulus.bitLength()))
      .toRight(OptionEmpty.label("modulusBitLength"))
      .flatMap(bitLength => atOrAbove(bitLength, 2048).label("bitLength").as(()))
end jwa
