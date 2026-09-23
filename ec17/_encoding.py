"""压缩点编码与标量编码（教学协议子集，固定长度、唯一规范形式）。

点编码（SEC1 风格，坐标只用 1 字节因为域为 F_17）：
  - 无穷远点：``0x00``（恰好 1 字节）；
  - 有限点 (x, y)：``prefix || x``，共 2 字节，
    ``prefix = 0x02`` 当 y 为偶数，``0x03`` 当 y 为奇数，``x`` 为单字节。

拒绝规则（不静默纠正）：
  - 空输入、截断输入 → Empty/TruncatedEncodingError；
  - 首字节不是 0x00/0x02/0x03 → InvalidEncodingPrefixError；
  - 点 x ≥ 17、标量 ≥ 19 → OutOfDomainEncodingError；
  - 任何尾随字节、0x00 后再带字节等非最短形式 → NonShortestEncodingError；
  - x 在域内但该 x 上不存在对应曲线点（右式为二次非剩余）→ PointNotOnCurveError。

注意：奇偶前缀“翻转”本身能解码成另一个合法点（原点点的负点），
它不属于编码错误；是否接受由验签等式判定（通常以 SignatureMismatchError 拒绝）。
"""

from ._errors import (
    TypeValidationError,
    PointAtInfinityError,
    EmptyEncodingError,
    TruncatedEncodingError,
    InvalidEncodingPrefixError,
    OutOfDomainEncodingError,
    NonShortestEncodingError,
    PointNotOnCurveError,
)
from ._curve import FIELD_PRIME, COEFF_A, COEFF_B, Point

PREFIX_INFINITY = 0x00
PREFIX_EVEN_Y = 0x02
PREFIX_ODD_Y = 0x03


def _as_bytes(name: str, data) -> bytes:
    if isinstance(data, str):
        raise TypeValidationError(
            f"参数 {name!r} 必须是 bytes/bytearray/memoryview，收到 str（不隐式按文本编码）"
        )
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeValidationError(
            f"参数 {name!r} 必须是 bytes/bytearray/memoryview，收到 {type(data).__name__}"
        )
    return bytes(data)


def encode_point(point) -> bytes:
    """把点编码为规范字节串：无穷远 → ``b'\\x00'``，有限点 → 2 字节压缩编码。"""
    if point is None:
        return bytes((PREFIX_INFINITY,))
    if not isinstance(point, tuple) or len(point) != 2:
        raise TypeValidationError(
            f"点必须是长度为 2 的 tuple (x, y)，收到 {type(point).__name__}: {point!r}"
        )
    # 复用曲线层的完整校验（域 + 方程），错误可定位。
    from ._curve import _validate_finite_point

    x, y = _validate_finite_point("point", point)
    prefix = PREFIX_EVEN_Y if y % 2 == 0 else PREFIX_ODD_Y
    return bytes((prefix, x))


def _point_from_compressed(prefix: int, x: int) -> Point:
    """由 (奇偶前缀, x) 还原唯一有限点；不存在则抛 PointNotOnCurveError。"""
    rhs = (x * x * x + COEFF_A * x + COEFF_B) % FIELD_PRIME
    roots = [y for y in range(FIELD_PRIME) if (y * y) % FIELD_PRIME == rhs]
    if not roots:
        raise PointNotOnCurveError(
            f"压缩编码 x={x} 在 F_{FIELD_PRIME} 上无曲线点"
            f"（x³+{COEFF_A}x+{COEFF_B}={rhs} 是二次非剩余）"
        )
    want_even = prefix == PREFIX_EVEN_Y
    for y in roots:
        if (y % 2 == 0) == want_even:
            return (x, y)
    # 两个平方根一奇一偶，理论上不可达；保留以防推理失误。
    raise PointNotOnCurveError(f"压缩编码 (prefix=0x{prefix:02x}, x={x}) 无匹配奇偶的点")


def decode_point(data, *, allow_infinity: bool = True):
    """严格解码压缩点编码。

    ``allow_infinity=False`` 时，``0x00`` 抛 :class:`PointAtInfinityError`
    （验签位置 R/P 不允许无穷远）。
    """
    raw = _as_bytes("data", data)
    if len(raw) == 0:
        raise EmptyEncodingError("点编码为空（至少需要 1 字节）")

    first = raw[0]
    if len(raw) == 1:
        if first == PREFIX_INFINITY:
            if not allow_infinity:
                raise PointAtInfinityError(
                    "点编码 0x00 表示无穷远点，此处要求有限点"
                )
            return None
        if first in (PREFIX_EVEN_Y, PREFIX_ODD_Y):
            raise TruncatedEncodingError(
                f"点编码被截断：前缀 0x{first:02x} 后缺少 1 字节 x 坐标"
            )
        raise InvalidEncodingPrefixError(
            f"点编码首字节 0x{first:02x} 非法（只允许 0x00/0x02/0x03）"
        )

    if len(raw) > 2:
        raise NonShortestEncodingError(
            f"点编码长度为 {len(raw)} 字节，压缩点必须恰为 2 字节（拒绝尾随字节）"
        )

    # len == 2
    if first == PREFIX_INFINITY:
        raise NonShortestEncodingError(
            "无穷远点的唯一最短编码是单字节 0x00，0x00 后不允许携带字节"
        )
    if first not in (PREFIX_EVEN_Y, PREFIX_ODD_Y):
        raise InvalidEncodingPrefixError(
            f"点编码首字节 0x{first:02x} 非法（有限点只允许 0x02/0x03）"
        )

    x = raw[1]
    if x >= FIELD_PRIME:
        raise OutOfDomainEncodingError(
            f"点编码 x={x} 超出域 F_{FIELD_PRIME}（要求 0..{FIELD_PRIME - 1}）"
        )
    return _point_from_compressed(first, x)


def encode_scalar(n: int) -> bytes:
    """把 0..18 的标量编码为 1 字节最短形式（bool 与越界值拒绝）。"""
    from ._curve import _validate_scalar

    value = _validate_scalar("n", n)
    return bytes((value,))


def decode_scalar(data, *, name: str = "scalar") -> int:
    """解码 1 字节标量；空/截断、非最短、≥19 全部拒绝。"""
    raw = _as_bytes("data", data)
    if len(raw) == 0:
        raise EmptyEncodingError(f"标量 {name!r} 编码为空（需要恰好 1 字节）")
    if len(raw) > 1:
        raise NonShortestEncodingError(
            f"标量 {name!r} 编码长度为 {len(raw)} 字节，必须恰为 1 字节（拒绝尾随字节）"
        )
    value = raw[0]
    from ._curve import GROUP_ORDER

    if value >= GROUP_ORDER:
        raise OutOfDomainEncodingError(
            f"标量 {name}={value} 超出 Z_{GROUP_ORDER}（要求 0..{GROUP_ORDER - 1}）"
        )
    return value
