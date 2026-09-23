"""Schnorr 风格教学签名（仅教学，不安全）。

协议（本题的有限子集，非任何行业标准的完整实现）：
  - 私钥 sk ∈ {1..18}，公钥 P = sk·G；
  - 签名时由调用方显式提供 nonce k ∈ {1..18}（不使用随机源，也不做
    RFC 6979 式派生；教学库禁止从密钥文件读取真实密钥）；
  - R = k·G；质询 e = SHA256( encode(R) ∥ encode(P) ∥ message ) mod 19；
  - 签名为 (R, s)，其中 s = (k + e·sk) mod 19；
  - 验签：要求 s ∈ 0..18、R 与 P 均为曲线上的有限点，重算 e 后检查
    s·G = R + e·P。

验签错误语义：
  - 结构/类型/范围非法（R 或 P 为无穷远点或不在曲线上、s 越界、消息类型
    错误等）抛对应异常，错误信息可定位，不静默纠正；
  - 对结构完全合法但等式不成立的签名，:func:`verify` 返回 ``False``，
    :func:`assert_verify` 抛 :class:`SignatureMismatchError`。

.. warning::
   群只有 19 个元素，私钥空间可瞬间穷举；nonce 由调用方给且不防重用。
   本模块**仅用于教学演示**，不提供任何真实安全性。
"""

from dataclasses import dataclass
import hashlib

from ._errors import (
    TypeValidationError,
    PointAtInfinityError,
    ScalarOutOfRangeError,
    SignatureMismatchError,
    InvalidSecretKeyError,
    InvalidNonceError,
    MessageTypeError,
    MessageTooLongError,
)
from ._curve import (
    GROUP_ORDER,
    GENERATOR,
    Point,
    point_add,
    scalar_mul,
    _validate_finite_point,
    _reject_nonint,
)
from ._encoding import (
    encode_point,
    decode_point,
    encode_scalar,
    decode_scalar,
    EmptyEncodingError,
    TruncatedEncodingError,
    NonShortestEncodingError,
)

#: 消息长度上限（字节）。题面未给更小值，取 2^16-1 作为接口边界。
MAX_MESSAGE_BYTES = 65_535


@dataclass(frozen=True)
class Signature:
    """教学签名 (R, s) 及其消息。字段只读。"""

    r: Point
    s: int
    message: bytes

    def __post_init__(self):
        # 仅在构造时做形状/类型约束；完整曲线校验发生在验签处。
        if self.r is None:
            raise PointAtInfinityError("Signature.r 不能是无穷远点")
        if not isinstance(self.r, tuple) or len(self.r) != 2:
            raise TypeValidationError(
                f"Signature.r 必须是有限点 (x, y)，收到 {self.r!r}"
            )
        _reject_nonint("s", self.s)
        if not 0 <= self.s < GROUP_ORDER:
            raise ScalarOutOfRangeError(
                f"Signature.s={self.s} 超出 0..{GROUP_ORDER - 1}"
            )
        if not isinstance(self.message, (bytes, bytearray)):
            raise MessageTypeError(
                f"Signature.message 必须是 bytes，收到 {type(self.message).__name__}"
            )
        if len(self.message) > MAX_MESSAGE_BYTES:
            raise MessageTooLongError(
                f"Signature.message 长度 {len(self.message)} 超过上限 {MAX_MESSAGE_BYTES}"
            )
        # dataclass(frozen=True) 下归一化存储为 bytes。
        object.__setattr__(self, "message", bytes(self.message))


def _validate_message(message) -> bytes:
    if isinstance(message, str):
        raise MessageTypeError("message 必须是 bytes（不隐式编码 str，请先显式 encode）")
    if not isinstance(message, (bytes, bytearray)):
        raise MessageTypeError(
            f"message 必须是 bytes/bytearray，收到 {type(message).__name__}"
        )
    if len(message) > MAX_MESSAGE_BYTES:
        raise MessageTooLongError(
            f"message 长度 {len(message)} 超过上限 {MAX_MESSAGE_BYTES} 字节"
        )
    return bytes(message)


def _validate_secret_key(secret_key) -> int:
    _reject_nonint("secret_key", secret_key)
    if not 1 <= secret_key < GROUP_ORDER:
        raise InvalidSecretKeyError(
            f"secret_key={secret_key} 必须是 1..{GROUP_ORDER - 1} 的整数"
            "（0 会导出无穷远公钥，越界值不做隐式约化）"
        )
    return secret_key


def _validate_nonce(nonce) -> int:
    _reject_nonint("nonce", nonce)
    if not 0 <= nonce < GROUP_ORDER:
        raise InvalidNonceError(
            f"nonce={nonce} 必须是 0..{GROUP_ORDER - 1} 的整数（不做隐式约化）"
        )
    if nonce == 0:
        raise InvalidNonceError("nonce=0 会使 R=k·G 成为无穷远点，禁止用于签名")
    return nonce


def _require_finite_curve_point(name: str, point) -> Point:
    """R/P 位的统一严格校验：拒绝无穷远、域外与不在曲线上的点。"""
    if point is None:
        raise PointAtInfinityError(f"参数 {name!r} 是无穷远点，验签要求有限点")
    return _validate_finite_point(name, point)


def derive_public_key(secret_key) -> Point:
    """由 1..18 的私钥导出公钥 P = sk·G（教学私钥，禁止使用真实密钥）。"""
    sk = _validate_secret_key(secret_key)
    return scalar_mul(sk, GENERATOR)


def challenge(r, public_key, message) -> int:
    """重算质询 e = SHA256(encode(R) ∥ encode(P) ∥ message) mod 19。"""
    msg = _validate_message(message)
    # challenge 允许对无穷远点编码参与哈希（编码层支持）；但 R/P 有限点必须
    # 经过完整校验。验签/签名路径上二者都已是有限点。
    if r is not None:
        _validate_finite_point("r", r)
    if public_key is not None:
        _validate_finite_point("public_key", public_key)
    digest_input = encode_point(r) + encode_point(public_key) + msg
    return int.from_bytes(hashlib.sha256(digest_input).digest(), "big") % GROUP_ORDER


def sign(secret_key, message, nonce) -> Signature:
    """用显式 nonce 生成教学签名 (R, s)。

    不读取任何密钥文件、不访问随机源；nonce 重用会在教学上直接暴露私钥，
    调用方责任自负（本库就是用来演示这些问题的）。
    """
    msg = _validate_message(message)
    sk = _validate_secret_key(secret_key)
    k = _validate_nonce(nonce)

    r_point = scalar_mul(k, GENERATOR)
    # 群阶为素数且 k ∈ 1..18，数学上 R 必为有限点；防御性保留该分支。
    if r_point is None:  # pragma: no cover - 由 nonce 校验在输入侧排除
        raise InvalidNonceError("nonce 导出的 R 是无穷远点")

    public_key = scalar_mul(sk, GENERATOR)
    e = challenge(r_point, public_key, msg)
    s = (k + e * sk) % GROUP_ORDER
    return Signature(r=r_point, s=s, message=msg)


def assert_verify(message, public_key, r, s) -> None:
    """严格验签：结构非法抛可定位异常；等式不成立抛 SignatureMismatchError。"""
    msg = _validate_message(message)
    _require_finite_curve_point("public_key", public_key)
    _require_finite_curve_point("r", r)
    _reject_nonint("s", s)
    if not 0 <= s < GROUP_ORDER:
        raise ScalarOutOfRangeError(
            f"s={s} 超出规范范围 0..{GROUP_ORDER - 1}"
            "（例如 s+19 不被接受，模 19 可塑性在编码层即被拒绝）"
        )

    e = challenge(r, public_key, msg)
    lhs = scalar_mul(s, GENERATOR)
    rhs = point_add(r, scalar_mul(e, public_key))
    if lhs != rhs:
        raise SignatureMismatchError(
            f"验签失败：s·G={lhs} ≠ R + e·P={rhs}（R={r}, s={s}, e={e}）"
        )


def verify(message, public_key, r, s) -> bool:
    """严格验签的布尔版本。

    结构非法（无穷远点、点不在曲线上、s 越界、消息非法等）照常抛异常；
    仅对“结构合法但等式不成立”的签名返回 ``False``。
    """
    try:
        assert_verify(message, public_key, r, s)
    except SignatureMismatchError:
        return False
    return True


def encode_signature(signature: Signature) -> bytes:
    """把签名编码为固定 3 字节：encode(R)（2 字节）∥ s（1 字节）。"""
    if not isinstance(signature, Signature):
        raise TypeValidationError(
            f"signature 必须是 Signature，收到 {type(signature).__name__}"
        )
    return encode_point(signature.r) + encode_scalar(signature.s)


def decode_signature(data, message) -> Signature:
    """解码 3 字节签名并绑定消息；长度不符、R 无穷远、s≥19 全部拒绝。"""
    if isinstance(data, str) or not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeValidationError(
            f"data 必须是 bytes/bytearray/memoryview，收到 {type(data).__name__}"
        )
    raw = bytes(data)
    if len(raw) == 0:
        raise EmptyEncodingError("签名编码为空（需要恰好 3 字节：2 字节 R + 1 字节 s）")
    if len(raw) < 3:
        raise TruncatedEncodingError(
            f"签名编码被截断：长度 {len(raw)}，需要恰好 3 字节（2 字节 R + 1 字节 s）"
        )
    if len(raw) > 3:
        raise NonShortestEncodingError(
            f"签名编码长度 {len(raw)}，必须恰为 3 字节（拒绝尾随字节）"
        )
    r_point = decode_point(raw[:2], allow_infinity=False)
    s_value = decode_scalar(raw[2:3], name="s")
    return Signature(r=r_point, s=s_value, message=_validate_message(message))


def verify_encoded(message, public_key_enc, r_enc, s_enc) -> bool:
    """编码入口的严格验签。

    ``public_key_enc`` / ``r_enc`` 为压缩点编码，``s_enc`` 为 1 字节标量编码；
    全部按严格规则解码（拒绝无穷远、非最短与域外编码），再做等式检查。
    """
    msg = _validate_message(message)
    public_key = decode_point(public_key_enc, allow_infinity=False)
    r_point = decode_point(r_enc, allow_infinity=False)
    s_value = decode_scalar(s_enc, name="s")
    return verify(msg, public_key, r_point, s_value)
