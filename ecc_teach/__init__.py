"""ecc_teach —— 椭圆曲线教学签名的严格验签可复用模块（TEACHING ONLY）。

固定小素数曲线 y² = x³ + 2x + 2 mod 17，基点 G=(5,1)，阶 19。
仅用于离线密码工程教学，**不安全，禁止用于真实密钥或真实场景**。

公开接口见 :mod:`ecc_teach.core`；错误类型见 :mod:`ecc_teach.errors`。
"""

from __future__ import annotations

from .core import (
    A_COEF,
    B_COEF,
    GENERATOR,
    INFINITY_ENCODING,
    MAX_MESSAGE_BYTES,
    ORDER,
    PREFIX_EVEN,
    PREFIX_ODD,
    P_MOD,
    Point,
    Signature,
    challenge,
    decode_point,
    derive_public_key,
    encode_point,
    is_infinity,
    is_on_curve,
    point_add,
    point_double,
    point_neg,
    scalar_mult,
    sign_scalar,
    is_signature_valid,
    verify_signature,
)
from .errors import (
    ECCTeachError,
    EncodingError,
    InvalidPointError,
    InvalidSignatureError,
    MessageTooLongError,
    NonFiniteNumberError,
    StrictTypeError,
)

__all__ = [
    # 常量
    "P_MOD",
    "A_COEF",
    "B_COEF",
    "GENERATOR",
    "ORDER",
    "MAX_MESSAGE_BYTES",
    "PREFIX_EVEN",
    "PREFIX_ODD",
    "INFINITY_ENCODING",
    # 数据结构
    "Point",
    "Signature",
    # 点运算
    "is_infinity",
    "point_neg",
    "is_on_curve",
    "point_add",
    "point_double",
    "scalar_mult",
    # 编码
    "encode_point",
    "decode_point",
    # 签名
    "derive_public_key",
    "challenge",
    "sign_scalar",
    "verify_signature",
    "is_signature_valid",
    # 错误
    "ECCTeachError",
    "StrictTypeError",
    "NonFiniteNumberError",
    "InvalidPointError",
    "EncodingError",
    "MessageTooLongError",
    "InvalidSignatureError",
]

__version__ = "1.0.0"
