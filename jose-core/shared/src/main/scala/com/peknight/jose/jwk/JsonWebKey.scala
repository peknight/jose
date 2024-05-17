package com.peknight.jose.jwk

import com.peknight.jose.jwa.JsonWebAlgorithm

/**
 * https://datatracker.ietf.org/doc/html/rfc7517
 */
trait JsonWebKey:
  def keyType: KeyType
  def publicKeyUseType: Option[PublicKeyUseType]
  def keyOperations: Seq[KeyOperationType]
  def algorithm: JsonWebAlgorithm
  
end JsonWebKey
