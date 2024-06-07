package com.peknight.jose.jwk

import com.peknight.codec.base.Base64Url

case class OtherPrimesInfo(
                            /**
                             * The "r" (prime factor) parameter within an "oth" array member
                             * represents the value of a subsequent prime factor.  It is represented
                             * as a Base64urlUInt-encoded value.
                             */
                            primeFactor: Base64Url,
                            /**
                             * The "d" (factor CRT exponent) parameter within an "oth" array member
                             * represents the CRT exponent of the corresponding prime factor.  It is
                             * represented as a Base64urlUInt-encoded value.
                             */
                            factorCRTExponent: Base64Url,
                            /**
                             * The "k" (key value) parameter contains the value of the symmetric (or
                             * other single-valued) key.  It is represented as the base64url
                             * encoding of the octet sequence containing the key value.
                             */
                            factorCRTCoefficient: Base64Url
                          )
