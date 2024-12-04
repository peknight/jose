package com.peknight.jose.error

import com.peknight.error.Error
import com.peknight.jose.jwx.JsonWebStructure


trait UnsupportedJsonWebStructure extends JoseError:
  def structure: JsonWebStructure
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unsupported JsonWebStructure $structure")
end UnsupportedJsonWebStructure
object UnsupportedJsonWebStructure:
  private case class UnsupportedJsonWebStructure(structure: JsonWebStructure)
    extends com.peknight.jose.error.UnsupportedJsonWebStructure
  def apply[A](structure: JsonWebStructure): com.peknight.jose.error.UnsupportedJsonWebStructure =
    UnsupportedJsonWebStructure(structure)
end UnsupportedJsonWebStructure
