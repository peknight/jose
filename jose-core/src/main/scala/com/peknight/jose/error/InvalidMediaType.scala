package com.peknight.jose.error

import org.http4s.MediaType

trait InvalidMediaType extends JoseError:
  def expected: MediaType
  def actual: MediaType
  override def lowPriorityMessage: Option[String] = Some(s"Invalid MediaType: expected $expected, got $actual")
end InvalidMediaType
object InvalidMediaType:
  private case class InvalidMediaType(expected: MediaType, actual: MediaType)
    extends com.peknight.jose.error.InvalidMediaType
  def apply(expected: MediaType, actual: MediaType): com.peknight.jose.error.InvalidMediaType =
    InvalidMediaType(expected, actual)
end InvalidMediaType
