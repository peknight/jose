package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.commons.bigint.syntax.byteVector.toUnsignedBigInt
import com.peknight.jose.error.jws.{InvalidECDSAKey, InvalidECDSASignatureFormat, JsonWebSignatureError}
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwa.signature.ECDSAAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.signature.Signature
import scodec.bits.ByteVector

import java.security.interfaces.{ECKey, ECPrivateKey, ECPublicKey}
import java.security.{Key, SecureRandom, Provider as JProvider}

object ECDSAOps extends SignatureOps[ECDSAAlgorithm, ECPrivateKey, ECPublicKey]:
  def typedSign[F[_] : Sync](algorithm: ECDSAAlgorithm, key: ECPrivateKey, data: ByteVector,
                             useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                             random: Option[SecureRandom] = None): F[Either[JsonWebSignatureError, ByteVector]] =
    Signature.sign[F](algorithm.signature, key, data, provider = provider, random = random)
      .map(derEncodedBytes => convertDERToConcatenated(derEncodedBytes, algorithm.signatureByteLength))

  def typedVerify[F[_] : Sync](algorithm: ECDSAAlgorithm, key: ECPublicKey, data: ByteVector, signed: ByteVector,
                               useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]] =
    if signed.length > algorithm.signatureByteLength then false.asRight.pure[F]
    else
      val rBytes = leftHalf(signed)
      val sBytes = rightHalf(signed)
      val r = rBytes.toUnsignedBigInt
      val s = sBytes.toUnsignedBigInt
      val ecParams = algorithm.curve.std.ecParameterSpec
      val orderN = BigInt(ecParams.getOrder)
      if r.mod(orderN) == BigInt(0) || s.mod(orderN) == BigInt(0) then false.asRight.pure[F]
      else
        convertConcatenatedToDER(signed) match
          case Right(signed) => Signature.publicKeyVerify[F](algorithm.signature, key, data, signed, provider)
            .map(_.asRight)
          case Left(error) => error.asLeft.pure[F]
  end typedVerify

  def typedValidateSigningKey(algorithm: ECDSAAlgorithm, key: ECPrivateKey): Either[JsonWebSignatureError, Unit] =
    validateKey(algorithm, key)

  def typedValidateVerificationKey(algorithm: ECDSAAlgorithm, key: ECPublicKey): Either[JsonWebSignatureError, Unit] =
    validateKey(algorithm, key)

  def validateKey(algorithm: ECDSAAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    key match
      case k: ECKey =>
        val curve = Curve.curveMap.get(k.getParams.getCurve)
        if Curve.curveMap.get(k.getParams.getCurve).contains(algorithm.curve) then Left(InvalidECDSAKey(algorithm, curve))
        else Right(())
      case _ => Right(())

  // Convert the DER encoding of R and S into a concatenation of R and S
  private def convertDERToConcatenated(derEncodedBytes: ByteVector, outputLength: Int): Either[JsonWebSignatureError, ByteVector] =
    for
      // 1. 验证输入有效性
      // 首先检查输入的DER编码字节长度是否至少为8，以及字节数组的第一个字节（derEncodedBytes[0]）是否为48（表示SEQUENCE标签），以确保输入是一个有效的DER编码的ECDSA签名。
      _ <- if derEncodedBytes.length < 8 || derEncodedBytes.head != 48 then Left(InvalidECDSASignatureFormat) else Right(())
      // 2. 计算偏移量（offset）
      // 根据DER编码规则，长度字段可能占用1或2个字节。如果长度字节大于0，则偏移量为2；如果长度字节为0x81，则偏移量为3，因为这表示接下来有一个字节来指示实际长度。
      second = derEncodedBytes(1)
      offset <- if second > 0 then Right(2) else if second == 0x81.byteValue then Right(3) else Left(InvalidECDSASignatureFormat)
      // 3. 解析R值的长度和前导零
      // 计算R值的长度（rLength），并去除R值前面的无意义前导零，找到实际数据的起始位置。这是通过从R值结束位置反向遍历并找到第一个非零字节来完成的。
      rLength = derEncodedBytes(offset + 1)
      rBytes = derEncodedBytes.drop(offset + 2).take(rLength).dropWhile(_ == 0)
      // 4. 解析S值的长度和前导零
      // 同样地，计算S值的长度（sLength）并去除其前导零。
      sLength = derEncodedBytes(offset + rLength + 3)
      sBytes = derEncodedBytes.drop(offset + rLength + 4).take(sLength).dropWhile(_ == 0)
      // 5. 确定输出字节的长度（rawLen）
      // 确定最终输出的每个整数（R和S）的最小需要长度，取R和S的实际无前导零长度中的较大者，并确保它至少是outputLength/2，以满足输出长度需求。
      rawLen = rBytes.length.max(sBytes.length).max(outputLength / 2)
      // 6. 验证DER编码结构的正确性
      // 检查DER编码的结构，包括前一个字节表示的后续数据长度是否与计算出的总长度匹配，以及R和S部分的编码是否符合预期格式。
      flag = (derEncodedBytes(offset - 1) & 0xff) != derEncodedBytes.length - offset ||
        (derEncodedBytes(offset - 1) & 0xff) != rLength + sLength + 4 ||
        derEncodedBytes(offset) != 2 ||
        derEncodedBytes(offset + rLength + 2) != 2
      _ <- if flag then Left(InvalidECDSASignatureFormat) else Right(())
    yield
      // 7. 创建并填充输出数组
      ByteVector.fill(rawLen - rBytes.length)(0) ++ rBytes ++ ByteVector.fill(rawLen - sBytes.length)(0) ++ sBytes

  // Convert the concatenation of R and S into DER encoding
  private def convertConcatenatedToDER(concatenatedSignatureBytes: ByteVector): Either[JsonWebSignatureError, ByteVector] =
    def getBytes(rawBytes: ByteVector): ByteVector = rawBytes.init.dropWhile(_ == 0) :+ rawBytes.last
    def getLength(bytes: ByteVector): Long = if bytes.head < 0 then bytes.length + 1 else bytes.length
    val rBytes = getBytes(leftHalf(concatenatedSignatureBytes))
    val sBytes = getBytes(rightHalf(concatenatedSignatureBytes))
    val rLength = getLength(rBytes)
    val sLength = getLength(sBytes)
    val len = rLength + sLength + 4
    if len > 255 then Left(InvalidECDSASignatureFormat)
    else
      Right(48.byteValue +: ((if len < 128 then ByteVector.empty else ByteVector(0x81.byteValue)) ++ (len.byteValue +:
        2.byteValue +: rLength.byteValue +: (ByteVector.fill(rLength - rBytes.length)(0) ++ rBytes ++
        (2.byteValue +: sLength.byteValue +: (ByteVector.fill(sLength - sBytes.length)(0) ++ sBytes)))
      )))

  private def leftHalf(bytes: ByteVector): ByteVector = bytes.take(bytes.length / 2)
  private def rightHalf(bytes: ByteVector): ByteVector =
    val half = bytes.length / 2
    bytes.drop(half).take(half)

end ECDSAOps
