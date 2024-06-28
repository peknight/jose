package com.peknight.jose.jwa.ecc

import java.math.BigInteger
import java.security.spec.{ECFieldFp, ECParameterSpec, ECPoint, EllipticCurve}

trait `P-256KPlatform` extends ECParameterSpecPlatform:
  val ecParameterSpec: ECParameterSpec =
    new ECParameterSpec(
      new EllipticCurve(
        new ECFieldFp(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")),
        new BigInteger("0"),
        new BigInteger("7")
      ),
      new ECPoint(
        new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
        new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424")
      ),
      new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337"),
      1
    )
end `P-256KPlatform`
