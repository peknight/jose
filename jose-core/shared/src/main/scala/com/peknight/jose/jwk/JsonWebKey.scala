package com.peknight.jose.jwk

trait JsonWebKey:
  def keyType: KeyType
  def publicKeyUseType: Option[PublicKeyUseType]
  def keyOperations: Seq[KeyOperationType]
end JsonWebKey
