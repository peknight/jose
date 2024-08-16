package com.peknight.jose.jws

import com.peknight.jose.jws.Signature.Signature

case class JsonWebSignatures(payload: String, signatures: List[Signature])
