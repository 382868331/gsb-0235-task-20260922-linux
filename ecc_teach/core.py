"""椭圆曲线教学签名 —— 核心模块。

曲线（小素数教学曲线，固定且不可配置）::

    E: y^2 = x^3 + 2x + 2  (mod 17)
    基点 G = (5, 1)，素数阶 n = 19（穷举可证，含无穷远点全群共 19 个点）

Schnorr 风格教学签名：

    e = SHA256( R编码 ‖ P编码 ‖ message ) mod 19
    签名（教学合成，nonce 显式给出）：s = k + e*d mod 19，R = kG
    验签：s 必须在 0..18；R、P 必须是非无穷远的曲线点；
          检查 sG = R + eP。

警告（TEACHING ONLY / NOT SECURE）
----------------------------------
群只有 19 个元素，私钥空间只有 18 个非零值，任何人都可瞬间穷举；
SHA-256 输出被折叠到 19 以内，碰撞平凡。本模块**禁止**用于真实密钥、
真实资产或任何需要安全保障的场景，仅用于离线密码工程教学演示。

本文件只实现题目契约的有限数学/协议子集，不宣称兼容任何行业标准
（不是 RFC 8032 / BIP-schnorr / sec1 完整实现）。
"""

from __future__ import annotations

import hashlib
import math
from typing import Optional, Tuple

from .errors import (
    EncodingError,
    InvalidPointError,
    InvalidSignatureError,
    MessageTooLongError,
    NonFiniteNumberError,
    StrictTypeError,
)

# ---------------------------------------------------------------------------
# 固定的公开域参数与接口上限
# ---------------------------------------------------------------------------

P_MOD = 17
"""曲线素域模数。"""

A_COEF = 2
"""曲线方程系数 a。"""

B_COEF = 2
"""曲线方程系数 b。"""

GENERATOR: "Point" = (5, 1)
"""基点 G。"""

ORDER = 19
"""G 的阶（素数），也是全部合法标量的模。"""

MAX_MESSAGE_BYTES = 65_536
"""消息长度上限（字节）。上限是接口边界，不是性能目标。"""

PREFIX_EVEN = 0x02
PREFIX_ODD = 0x03
PREFIX_INFINITY = 0x00
INFINITY_ENCODING = b"\x00"
"""无穷远点的规范（且唯一合法）压缩编码：单字节 0x00。"""

Point = Optional[Tuple[int, int]]
"""点的公开数据结构：``None`` 表示无穷远点 O，否则为 ``(x, y)`` 仿射点。"""


class Signature(Tuple[int, bytes]):
    """不可变签名结构 ``(s, r_encoding)``。

    - ``s``：响应标量，合法值 0..18；
    - ``r_encoding``：点 R 的最短压缩编码（33 字节风格，此处仅 2 字节）。

    它是一个真正的 tuple（可直接解包/比较），不可变；构造时**不做**
    密码学校验，非法签名必须交给 :func:`verify_signature` 拒绝。
    通过属性 ``.s`` / ``.r_encoding`` 或解包访问字段。
    """

    __slots__ = ()

    def __new__(cls, s: int, r_encoding: bytes) -> "Signature":
        return tuple.__new__(cls, (s, r_encoding))

    @property
    def s(self) -> int:
        return self[0]

    @property
    def r_encoding(self) -> bytes:
        return self[1]

    def __repr__(self) -> str:
        return f"Signature(s={self[0]!r}, r_encoding={self[1]!r})"


# ---------------------------------------------------------------------------
# 严格输入校验
# ---------------------------------------------------------------------------


def _check_exact_int(value: object, name: str) -> int:
    """要求精确的 int：拒绝 bool、拒绝 float（NaN/Inf 单独报错）、拒绝其它类型。"""
    if isinstance(value, bool):
        raise StrictTypeError(f"{name} 必须是精确 int，拒绝 bool（收到 {value!r}）")
    if isinstance(value, float):
        if math.isnan(value):
            raise NonFiniteNumberError(f"{name} 不能是 NaN")
        if not math.isfinite(value):
            raise NonFiniteNumberError(f"{name} 不能是带符号 Infinity（收到 {value!r}）")
        raise StrictTypeError(
            f"{name} 必须是精确 int，收到 float（{value!r}）；不做隐式取整"
        )
    if not isinstance(value, int):
        raise StrictTypeError(f"{name} 必须是精确 int，收到 {type(value).__name__}")
    return value


def _check_scalar_range(value: int, name: str, *, allow_zero: bool = True) -> int:
    low = 0 if allow_zero else 1
    if not low <= value <= ORDER - 1:
        label = "0..18" if allow_zero else "1..18"
        raise ValueError(f"{name} 必须在 {label}（模 {ORDER} 的代表元），收到 {value}")
    return value


def _check_message(message: object) -> bytes:
    """消息必须是精确 bytes 类型且长度不超上限。拒绝 str/bytearray/超长。"""
    if not isinstance(message, bytes):
        raise StrictTypeError(
            f"message 必须是精确 bytes，收到 {type(message).__name__}；"
            "请先显式编码（例如 .encode('utf-8')）"
        )
    if len(message) > MAX_MESSAGE_BYTES:
        raise MessageTooLongError(
            f"message 长度 {len(message)} 超过上限 {MAX_MESSAGE_BYTES} 字节"
        )
    return message


# ---------------------------------------------------------------------------
# 曲线点
# ---------------------------------------------------------------------------


def is_infinity(point: object) -> bool:
    """当且仅当点是无穷远点（``None``）。"""
    return point is None


def point_neg(point: Point) -> Point:
    """点的逆元：``-O = O``，``-(x,y) = (x, -y mod p)``。"""
    if point is None:
        return None
    _require_affine_on_curve(point, "point")
    x, y = point
    return (x, (-y) % P_MOD)


def is_on_curve(point: object) -> bool:
    """合法曲线点（含无穷远点）返回 True；结构/坐标/方程错误返回 False（不抛异常）。"""
    if point is None:
        return True
    if not isinstance(point, tuple) or len(point) != 2:
        return False
    x, y = point
    if isinstance(x, bool) or isinstance(y, bool):
        return False
    if not isinstance(x, int) or not isinstance(y, int):
        return False
    if not (0 <= x < P_MOD and 0 <= y < P_MOD):
        return False
    return (y * y - (x * x * x + A_COEF * x + B_COEF)) % P_MOD == 0


def _require_affine_on_curve(point: object, name: str = "point") -> Tuple[int, int]:
    """要求非无穷远点且在曲线上，返回 (x, y)，否则抛 InvalidPointError。"""
    if point is None:
        raise InvalidPointError(f"{name} 不能是无穷远点 O")
    if not isinstance(point, tuple) or len(point) != 2:
        raise InvalidPointError(
            f"{name} 必须是长度为 2 的 (x, y) tuple 或 None，收到 {point!r}"
        )
    x, y = point
    if isinstance(x, bool) or not isinstance(x, int) or isinstance(y, bool) or not isinstance(y, int):
        raise InvalidPointError(f"{name} 的坐标必须是精确 int（拒绝 bool/float），收到 {point!r}")
    if not (0 <= x < P_MOD and 0 <= y < P_MOD):
        raise InvalidPointError(f"{name} 的坐标必须在有限域 0..{P_MOD - 1} 内，收到 {point!r}")
    if (y * y - (x * x * x + A_COEF * x + B_COEF)) % P_MOD != 0:
        raise InvalidPointError(f"{name}={point!r} 不在曲线 y²=x³+{A_COEF}x+{B_COEF} mod {P_MOD} 上")
    return x, y


# ---------------------------------------------------------------------------
# 群运算（显式公式，不依赖任何第三方实现）
# ---------------------------------------------------------------------------


def _mod_inverse(value: int) -> int:
    """模逆；value=0 时除零没有逆元，抛 ZeroDivisionError。"""
    return pow(value % P_MOD, -1, P_MOD)


def point_add(left: Point, right: Point) -> Point:
    """点加 ``left + right``（相同点走倍点公式，互为逆元返回 O）。

    输入必须是合法曲线点，否则抛 :class:`InvalidPointError`。
    """
    if left is None:
        if not is_on_curve(right):
            raise InvalidPointError(f"right={right!r} 不是合法曲线点")
        return right
    if right is None:
        if not is_on_curve(left):
            raise InvalidPointError(f"left={left!r} 不是合法曲线点")
        return left

    x1, y1 = _require_affine_on_curve(left, "left")
    x2, y2 = _require_affine_on_curve(right, "right")

    if x1 == x2:
        if (y1 + y2) % P_MOD == 0:
            return None  # P + (-P) = O
        # 相同点：倍点 λ = (3x²+a)/(2y)
        lam = ((3 * x1 * x1 + A_COEF) * _mod_inverse(2 * y1)) % P_MOD
    else:
        lam = ((y2 - y1) * _mod_inverse(x2 - x1)) % P_MOD

    x3 = (lam * lam - x1 - x2) % P_MOD
    y3 = (lam * (x1 - x3) - y1) % P_MOD
    _require_affine_on_curve((x3, y3), "内部结果")  # 防御性自检
    return (x3, y3)


def point_double(point: Point) -> Point:
    """倍点 2P；O 的倍点仍是 O。"""
    if point is None:
        return None
    return point_add(point, point)


def scalar_mult(k: object, point: Point) -> Point:
    """标量乘法 k*P（双加，非恒定时间）。

    - k 必须是精确非负 int（拒绝 bool；负数无此教学契约，直接拒绝）；
    - point 必须是合法曲线点（允许 O）。
    """
    k_int = _check_exact_int(k, "k")
    if k_int < 0:
        raise ValueError(f"k 必须是非负整数，收到 {k_int}")
    if not is_on_curve(point):
        raise InvalidPointError(f"point={point!r} 不是合法曲线点")

    result: Point = None
    addend: Point = point
    n = k_int
    while n:
        if n & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        n >>= 1
    return result


# ---------------------------------------------------------------------------
# 最短压缩编码
# ---------------------------------------------------------------------------
#
# 编码（固定 2 字节，仿射点）：
#   byte0 = 0x02（y 为偶）/ 0x03（y 为奇）
#   byte1 = x（0..16 的最短表示；x=17 已域外，任何 3 字节序列都非最短，拒绝）
# 无穷远点：单字节 0x00（仅在 allow_infinity=True 的上下文合法）。


def _y_roots_for_x(x: int) -> Tuple[int, ...]:
    """返回给定 x 处曲线上的全部 y（0、1 或 2 个，已排序）。"""
    rhs = (x * x * x + A_COEF * x + B_COEF) % P_MOD
    roots = tuple(sorted(y for y in range(P_MOD) if (y * y) % P_MOD == rhs))
    return roots


def encode_point(point: Point, *, allow_infinity: bool = False) -> bytes:
    """把曲线点编码为最短压缩字节串。

    - 仿射点 -> ``b'\\x02'/'\\x03' + 单字节 x``；
    - 无穷远点 -> ``b'\\x00'``，仅当 ``allow_infinity=True``；
    - 非法点抛 :class:`InvalidPointError`。
    """
    if point is None:
        if not allow_infinity:
            raise InvalidPointError("此编码上下文不允许无穷远点 O")
        return INFINITY_ENCODING

    x, y = _require_affine_on_curve(point, "point")
    prefix = PREFIX_EVEN if y % 2 == 0 else PREFIX_ODD
    return bytes((prefix, x))


def decode_point(data: object, *, allow_infinity: bool = False) -> Point:
    """严格解码最短压缩点编码。

    拒绝：非 bytes、空串/截断、3 字节及以上（非最短）、前缀非法、
    x 域外（17 或更大）、奇偶前缀与实际点不符、该 x 曲线上无点。
    无穷远编码 0x00 仅在 ``allow_infinity=True`` 接受。
    """
    if not isinstance(data, bytes):
        raise EncodingError(
            f"点编码必须是精确 bytes，收到 {type(data).__name__}"
        )

    if len(data) == 1:
        if data[0] == PREFIX_INFINITY:
            if allow_infinity:
                return None
            raise EncodingError("单字节 0x00 表示无穷远点，但此上下文禁止无穷远点")
        raise EncodingError(f"单字节编码前缀 0x{data[0]:02x} 非法（截断或伪造）")

    if len(data) != 2:
        raise EncodingError(
            f"编码长度 {len(data)} 字节：仿射点编码必须恰为 2 字节（最短形式），"
            "前导零/多余后缀均属非最短编码"
        )

    prefix, x = data[0], data[1]
    if prefix not in (PREFIX_EVEN, PREFIX_ODD):
        raise EncodingError(f"前缀 0x{prefix:02x} 非法（仅允许 0x02/0x03）")
    if not 0 <= x < P_MOD:
        raise EncodingError(f"x=0x{x:02x}({x}) 在有限域 F_{P_MOD} 之外（最短编码下域外）")

    roots = _y_roots_for_x(x)
    if not roots:
        raise EncodingError(f"x={x} 在曲线上没有对应 y（域外点，非二次剩余）")

    want_even = prefix == PREFIX_EVEN
    for y in roots:
        if (y % 2 == 0) == want_even:
            point = (x, y)
            _require_affine_on_curve(point, "解码结果")  # 防御性自检
            return point

    parity = "偶(0x02)" if want_even else "奇(0x03)"
    raise EncodingError(f"错误奇偶：x={x} 处没有{parity}的曲线点（压缩前缀被篡改）")


# ---------------------------------------------------------------------------
# Schnorr 风格教学签名
# ---------------------------------------------------------------------------


def derive_public_key(secret_scalar: object) -> bytes:
    """由教学私钥标量 d（1..18）计算压缩编码公钥 P=dG。

    d=0 会给出无穷远点公钥，直接拒绝；19 及以上/负数同样拒绝。
    """
    d = _check_exact_int(secret_scalar, "secret_scalar")
    _check_scalar_range(d, "secret_scalar", allow_zero=False)
    public = scalar_mult(d, GENERATOR)
    return encode_point(public)  # d ∈ 1..18、G 阶 19，必为非无穷远仿射点


def challenge(r_point: Point, public_point: Point, message: bytes) -> int:
    """e = SHA256( R编码 ‖ P编码 ‖ message ) mod 19。

    R、P 必须是**非无穷远**曲线点；message 为精确 bytes。
    """
    r = _require_affine_on_curve(r_point, "R")
    p_pub = _require_affine_on_curve(public_point, "P")
    msg = _check_message(message)
    preimage = encode_point(r) + encode_point(p_pub) + msg
    digest = hashlib.sha256(preimage).digest()
    return int.from_bytes(digest, "big") % ORDER


def sign_scalar(secret_scalar: object, message: object, nonce: object) -> Signature:
    """教学签名合成（确定性测试用，nonce 必须由调用方显式提供）。

        R = kG，e = SHA256(R‖P‖m) mod 19，s = k + e*d mod 19

    - secret_scalar：1..18 的精确 int；
    - nonce：1..18 的精确 int（0/19 会使 R=O，验签必败，故直接拒绝）；
    - message：精确 bytes，长度 ≤ MAX_MESSAGE_BYTES。

    本函数不读取、不写入任何密钥文件；教学模块禁止真实密钥。
    """
    d = _check_exact_int(secret_scalar, "secret_scalar")
    _check_scalar_range(d, "secret_scalar", allow_zero=False)
    k = _check_exact_int(nonce, "nonce")
    _check_scalar_range(k, "nonce", allow_zero=False)
    msg = _check_message(message)

    r_point = scalar_mult(k, GENERATOR)  # k ∈ 1..18 => R 必非 O
    public_point = scalar_mult(d, GENERATOR)
    e = challenge(r_point, public_point, msg)
    s = (k + e * d) % ORDER
    return Signature(s, encode_point(r_point))


def verify_signature(public_encoding: object, message: object, signature: object) -> bool:
    """严格验签；通过返回 True，否则抛 :class:`InvalidSignatureError`。

    检查顺序（原因码即按此顺序暴露第一个失败）：

    1. ``s_range``：s 必须是精确 int、非 bool、且在 0..18（s+19 之类模等价
       可塑性一律拒绝，不静默取模）；
    2. ``public_key_encoding`` / ``public_key_infinity``：公钥编码必须可严格
       解码、非无穷远、在曲线上；
    3. ``r_encoding`` / ``r_infinity``：R 编码同理；
    4. 计算 e=SHA256(R‖P‖message) mod 19；
    5. ``equation_fail``：检查 sG = R + eP。

    message 类型/长度错误抛 :class:`StrictTypeError` /
    :class:`MessageTooLongError`，签名结构类型错误抛
    :class:`StrictTypeError`——这些是调用契约错误，与“密码学上无效”分开。
    """
    msg = _check_message(message)

    if not isinstance(signature, Signature):
        raise StrictTypeError(
            f"signature 必须是 Signature（tuple 子类），收到 {type(signature).__name__}"
        )
    s_raw, r_encoding = signature[0], signature[1]

    s_value = _check_exact_int(s_raw, "s")
    if not 0 <= s_value <= ORDER - 1:
        raise InvalidSignatureError(
            "s_range", f"s={s_value} 超出 0..18；不接受 s+19 等模等价改写"
        )

    if not isinstance(public_encoding, bytes):
        raise StrictTypeError(
            f"public_encoding 必须是精确 bytes，收到 {type(public_encoding).__name__}"
        )
    try:
        public_point = decode_point(public_encoding, allow_infinity=True)
    except EncodingError as exc:
        raise InvalidSignatureError("public_key_encoding", str(exc)) from None
    if public_point is None:
        raise InvalidSignatureError("public_key_infinity", "公钥不能是无穷远点")

    if not isinstance(r_encoding, bytes):
        raise StrictTypeError(f"r_encoding 必须是精确 bytes，收到 {type(r_encoding).__name__}")
    try:
        r_point = decode_point(r_encoding, allow_infinity=True)
    except EncodingError as exc:
        raise InvalidSignatureError("r_encoding", str(exc)) from None
    if r_point is None:
        raise InvalidSignatureError("r_infinity", "R 不能是无穷远点")

    e = challenge(r_point, public_point, msg)

    lhs = scalar_mult(s_value, GENERATOR)
    rhs = point_add(r_point, scalar_mult(e, public_point))
    if lhs != rhs:
        raise InvalidSignatureError(
            "equation_fail", f"sG={lhs} 不等于 R+eP={rhs}（e={e}）"
        )
    return True


def is_signature_valid(public_encoding: object, message: object, signature: object) -> bool:
    """验签的布尔便捷形式：通过 True，密码学无效 False。

    仅吞 :class:`InvalidSignatureError`；契约级类型错误仍向外抛。
    """
    try:
        return verify_signature(public_encoding, message, signature)
    except InvalidSignatureError:
        return False


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
    # 类型
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
]
