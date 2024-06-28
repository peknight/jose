package com.peknight.jose.error

trait NoSuchCurve extends JsonWebKeyCreationError:
  override protected def lowPriorityLabelMessage(label: String): Option[String] = Some(s"No such curve: $label")
  override protected def lowPriorityMessage: Option[String] = Some("No such curve")
object NoSuchCurve extends NoSuchCurve
