package com.peknight.jose.error

trait UnrecognizedCriticalHeader extends JoseError:
  def header: String
  override protected def lowPriorityMessage: Option[String] = Some(s"Unrecognized header '$header' marked as critical.")
end UnrecognizedCriticalHeader
object UnrecognizedCriticalHeader:
  private case class UnrecognizedCriticalHeader(header: String) 
    extends com.peknight.jose.error.UnrecognizedCriticalHeader
  def apply(header: String): com.peknight.jose.error.UnrecognizedCriticalHeader = UnrecognizedCriticalHeader(header)
end UnrecognizedCriticalHeader
