package com.peknight.jose.jwa.ecc

trait prime256v1 extends `P-256`:
  override def name: String = "prime256v1"
end prime256v1
object prime256v1 extends prime256v1
