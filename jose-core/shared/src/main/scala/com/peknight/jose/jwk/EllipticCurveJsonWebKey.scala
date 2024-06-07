package com.peknight.jose.jwk

import com.peknight.codec.base.Base64Url
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.KeyType.EllipticCurve

trait EllipticCurveJsonWebKey extends JsonWebKey:
  def keyType: KeyType = EllipticCurve

  /**
   * The "crv" (curve) parameter identifies the cryptographic curve used
   * with the key.
   *
   * These values are registered in the IANA "JSON Web Key Elliptic Curve"
   * registry defined in Section 7.6.  Additional "crv" values can be
   * registered by other specifications.  Specifications registering
   * additional curves must define what parameters are used to represent
   * keys for the curves registered.  The "crv" value is a case-sensitive
   * string.
   *
   * SEC1 [SEC1] point compression is not supported for any of these three
   * curves.
   */
  def curve: Curve
  /**
   * The "x" (x coordinate) parameter contains the x coordinate for the
   * Elliptic Curve point.  It is represented as the base64url encoding of
   * the octet string representation of the coordinate, as defined in
   * Section 2.3.5 of SEC1 [SEC1].  The length of this octet string MUST
   * be the full size of a coordinate for the curve specified in the "crv"
   * parameter.  For example, if the value of "crv" is "P-521", the octet
   * string must be 66 octets long.
   */
  def xCoordinate: Base64Url
  /**
   * The "y" (y coordinate) parameter contains the y coordinate for the
   * Elliptic Curve point.  It is represented as the base64url encoding of
   * the octet string representation of the coordinate, as defined in
   * Section 2.3.5 of SEC1 [SEC1].  The length of this octet string MUST
   * be the full size of a coordinate for the curve specified in the "crv"
   * parameter.  For example, if the value of "crv" is "P-521", the octet
   * string must be 66 octets long.
   */
  def yCoordinate: Base64Url
  /**
   * The "d" (ECC private key) parameter contains the Elliptic Curve
   * private key value.  It is represented as the base64url encoding of
   * the octet string representation of the private key value, as defined
   * in Section 2.3.7 of SEC1 [SEC1].  The length of this octet string
   * MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the
   * curve).
   */
  def eccPrivateKey: Option[Base64Url]
end EllipticCurveJsonWebKey
