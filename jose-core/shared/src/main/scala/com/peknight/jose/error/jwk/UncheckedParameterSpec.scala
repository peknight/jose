package com.peknight.jose.error.jwk

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UncheckedParameterSpec[A] extends JsonWebKeyError:
  def parameterSpecType: ClassTag[A]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unchecked parameter spec: ${Error.errorClassTag(using parameterSpecType)}")
object UncheckedParameterSpec:
  private case class UncheckedParameterSpec[A](parameterSpecType: ClassTag[A])
    extends com.peknight.jose.error.jwk.UncheckedParameterSpec[A]
  def apply[A](using parameterSpecType: ClassTag[A]): com.peknight.jose.error.jwk.UncheckedParameterSpec[A] =
    UncheckedParameterSpec(parameterSpecType)
end UncheckedParameterSpec
