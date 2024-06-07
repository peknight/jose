package com.peknight.jose.jwa.encryption

sealed trait HeaderParam

object HeaderParam:

  sealed trait ECDHKeyAgreementHeaderParam extends HeaderParam

  /**
   * Ephemeral Public Key
   * The "epk" (ephemeral public key) value created by the originator for
   * the use in key agreement algorithms.  This key is represented as a
   * JSON Web Key [JWK] public key value.  It MUST contain only public key
   * parameters and SHOULD contain only the minimum JWK parameters
   * necessary to represent the key; other JWK parameters included can be
   * checked for consistency and honored, or they can be ignored.  This
   * Header Parameter MUST be present and MUST be understood and processed
   * by implementations when these algorithms are used.
   */
  case object epk extends ECDHKeyAgreementHeaderParam

  /**
   * Agreement PartyUInfo
   * The "apu" (agreement PartyUInfo) value for key agreement algorithms
   * using it (such as "ECDH-ES"), represented as a base64url-encoded
   * string.  When used, the PartyUInfo value contains information about
   * the producer.  Use of this Header Parameter is OPTIONAL.  This Header
   * Parameter MUST be understood and processed by implementations when
   * these algorithms are used.
   */
  case object apu extends ECDHKeyAgreementHeaderParam

  /**
   * Agreement PartyVInfo
   * The "apv" (agreement PartyVInfo) value for key agreement algorithms
   * using it (such as "ECDH-ES"), represented as a base64url encoded
   * string.  When used, the PartyVInfo value contains information about
   * the recipient.  Use of this Header Parameter is OPTIONAL.  This
   * Header Parameter MUST be understood and processed by implementations
   * when these algorithms are used.
   */
  case object apv extends ECDHKeyAgreementHeaderParam


  sealed trait AESGCMKeyEncryptionHeaderParam extends HeaderParam

  /**
   * Initialization Vector
   * The "iv" (initialization vector) Header Parameter value is the
   * base64url-encoded representation of the 96-bit IV value used for the
   * key encryption operation.  This Header Parameter MUST be present and
   * MUST be understood and processed by implementations when these
   * algorithms are used.
   */
  case object iv extends AESGCMKeyEncryptionHeaderParam

  /**
   * Authentication Tag
   * The "tag" (authentication tag) Header Parameter value is the
   * base64url-encoded representation of the 128-bit Authentication Tag
   * value resulting from the key encryption operation.  This Header
   * Parameter MUST be present and MUST be understood and processed by
   * implementations when these algorithms are used.
   */
  case object tag extends AESGCMKeyEncryptionHeaderParam

  sealed trait PBES2KeyEncryptionHeaderParam extends HeaderParam

  /**
   * PBES2 Salt Input
   * The "p2s" (PBES2 salt input) Header Parameter encodes a Salt Input
   * value, which is used as part of the PBKDF2 salt value.  The "p2s"
   * value is BASE64URL(Salt Input).  This Header Parameter MUST be
   * present and MUST be understood and processed by implementations when
   * these algorithms are used.
   */
  case object p2s extends PBES2KeyEncryptionHeaderParam

  /**
   * PBES2 Count
   * The "p2c" (PBES2 count) Header Parameter contains the PBKDF2
   * iteration count, represented as a positive JSON integer.  This Header
   * Parameter MUST be present and MUST be understood and processed by
   * implementations when these algorithms are used.
   */
  case object p2c extends PBES2KeyEncryptionHeaderParam
end HeaderParam