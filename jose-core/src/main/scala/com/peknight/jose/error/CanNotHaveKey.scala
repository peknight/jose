package com.peknight.jose.error

import com.peknight.jose.jwa.AlgorithmIdentifier

trait CanNotHaveKey extends JoseError:
  def identifier: AlgorithmIdentifier
  override def lowPriorityMessage: Option[String] = Some(s"${identifier.identifier} must not use a key")
end CanNotHaveKey
object CanNotHaveKey:
  private case class CanNotHaveKey(identifier: AlgorithmIdentifier) extends com.peknight.jose.error.CanNotHaveKey
  def apply(identifier: AlgorithmIdentifier): com.peknight.jose.error.CanNotHaveKey = CanNotHaveKey(identifier)
end CanNotHaveKey
