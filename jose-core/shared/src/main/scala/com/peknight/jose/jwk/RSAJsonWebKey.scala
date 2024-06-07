package com.peknight.jose.jwk

import com.peknight.codec.base.Base64Url
import com.peknight.jose.jwk.KeyType.RSA

trait RSAJsonWebKey extends JsonWebKey:
  def keyType: KeyType = RSA
  /**
   * The "n" (modulus) parameter contains the modulus value for the RSA
   * public key.  It is represented as a Base64urlUInt-encoded value.
   *
   * Note that implementers have found that some cryptographic libraries
   * prefix an extra zero-valued octet to the modulus representations they
   * return, for instance, returning 257 octets for a 2048-bit key, rather
   * than 256.  Implementations using such libraries will need to take
   * care to omit the extra octet from the base64url-encoded
   * representation.
   */
  def modulus: Base64Url
  /**
   * The "e" (exponent) parameter contains the exponent value for the RSA
   * public key.  It is represented as a Base64urlUInt-encoded value.
   *
   * For instance, when representing the value 65537, the octet sequence
   * to be base64url-encoded MUST consist of the three octets [1, 0, 1];
   * the resulting representation for this value is "AQAB".
   */
  def exponent: Base64Url
  /**
   * The "d" (private exponent) parameter contains the private exponent
   * value for the RSA private key.  It is represented as a Base64urlUInt-
   * encoded value.
   */
  def privateExponent: Option[Base64Url]
  /**
   * The "p" (first prime factor) parameter contains the first prime
   * factor.  It is represented as a Base64urlUInt-encoded value.
   */
  def firstPrimeFactor: Base64Url
  /**
   * The "q" (second prime factor) parameter contains the second prime
   * factor.  It is represented as a Base64urlUInt-encoded value.
   */
  def secondPrimeFactor: Base64Url
  /**
   * The "dp" (first factor CRT exponent) parameter contains the Chinese
   * Remainder Theorem (CRT) exponent of the first factor.  It is
   * represented as a Base64urlUInt-encoded value.
   */
  def firstFactorCRTExponent: Base64Url
  /**
   * The "dq" (second factor CRT exponent) parameter contains the CRT
   * exponent of the second factor.  It is represented as a Base64urlUInt-
   * encoded value.
   */
  def secondFactorCRTExponent: Base64Url
  /**
   * The "qi" (first CRT coefficient) parameter contains the CRT
   * coefficient of the second factor.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  def firstCRTCoefficient: Base64Url
  /**
   * The "oth" (other primes info) parameter contains an array of
   * information about any third and subsequent primes, should they exist.
   * When only two primes have been used (the normal case), this parameter
   * MUST be omitted.  When three or more primes have been used, the
   * number of array elements MUST be the number of primes used minus two.
   * For more information on this case, see the description of the
   * OtherPrimeInfo parameters in Appendix A.1.2 of RFC 3447 [RFC3447],
   * upon which the following parameters are modeled.  If the consumer of
   * a JWK does not support private keys with more than two primes and it
   * encounters a private key that includes the "oth" parameter, then it
   * MUST NOT use the key.
   */
  def otherPrimesInfo: Seq[OtherPrimesInfo]
end RSAJsonWebKey
