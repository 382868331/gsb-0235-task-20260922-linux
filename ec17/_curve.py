"""小素域椭圆曲线 y² = x³ + 2x + 2 (mod 17) 的群运算。

数据结构（公开契约）：
  - ``Point`` 是有限点，类型为 ``tuple[int, int]``，即 ``(x, y)``；
  - 无穷远点用 ``None`` 表示，常量名 :data:`INFINITY`。

本模块只含整数模运算，没有任何浮点路径。所有公开函数严格校验输入：
bool 不被当作整数、NaN/Infinity 等浮点值被拒绝、坐标必须在域内且在曲线上。
"""

import math

from ._errors import (
    TypeValidationError,
    CoordinateOutOfDomainError,
    PointNotOnCurveError,
    ScalarOutOfRangeError,
)

#: 域特征（素数）。
FIELD_PRIME = 17
#: 曲线方程系数 a（y² = x³ + a x + b）。
COEFF_A = 2
#: 曲线方程系数 b。
COEFF_B = 2
#: 基点 G 的素数阶（也是本群的元素个数）。
GROUP_ORDER = 19
#: 基点 G = (5, 1)。
GENERATOR = (5, 1)

#: 无穷远点（群单位元）。
INFINITY = None

Point = tuple[int, int]
"""仿射有限点 ``(x, y)``；无穷远点见 :data:`INFINITY`。"""

# 教学用点加调用计数器：只统计 point_add 实际执行的群加法次数，
# 供批验签演示“共享倍点表 vs 重复调用”的开销对比。不属于验签逻辑。
_POINT_ADD_CALLS = 0


def reset_point_add_counter() -> None:
    """把教学用点加计数器清零。"""
    global _POINT_ADD_CALLS
    _POINT_ADD_CALLS = 0


def point_add_count() -> int:
    """返回自上次清零以来 `point_add` 实际执行的群加法次数。"""
    return _POINT_ADD_CALLS


def _reject_nonint(name: str, value) -> None:
    """整数参数的统一类型校验：bool 一律拒绝；浮点（含 NaN/Infinity）拒绝。"""
    if isinstance(value, bool):
        raise TypeValidationError(
            f"参数 {name!r} 必须是 int，收到 bool（True/False 不被当作整数）"
        )
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeValidationError(
                f"参数 {name!r} 必须是有限整数，拒绝非有限浮点（NaN/Infinity）：{value}"
            )
        raise TypeValidationError(
            f"参数 {name!r} 必须是 int，收到 float（不做隐式取整）：{value}"
        )
    if not isinstance(value, int):
        raise TypeValidationError(f"参数 {name!r} 必须是 int，收到 {type(value).__name__}")


def _check_coordinate(name: str, value) -> int:
    _reject_nonint(name, value)
    if not 0 <= value < FIELD_PRIME:
        raise CoordinateOutOfDomainError(
            f"坐标 {name}={value} 超出域 F_{FIELD_PRIME}（要求 0..{FIELD_PRIME - 1}）"
        )
    return value


def is_on_curve(point) -> bool:
    """判断有限点是否满足曲线方程。

    - 传入 :data:`INFINITY` 返回 ``False``（无穷远是合法群元素，但不是“曲线上的仿射点”）；
    - 坐标类型非法（非整数、bool、NaN）抛 :class:`TypeValidationError`；
    - 坐标整数但超出 F_17 返回 ``False``（不抛异常，便于布尔查询）；
    - 坐标在域内但不满足方程返回 ``False``。
    """
    if point is INFINITY:
        return False
    if not isinstance(point, tuple) or len(point) != 2:
        raise TypeValidationError(
            f"点必须是长度为 2 的 tuple (x, y)，收到 {type(point).__name__}: {point!r}"
        )
    x, y = point
    _reject_nonint("x", x)
    _reject_nonint("y", y)
    if not (0 <= x < FIELD_PRIME and 0 <= y < FIELD_PRIME):
        return False
    return (y * y - (x * x * x + COEFF_A * x + COEFF_B)) % FIELD_PRIME == 0


def _validate_finite_point(name: str, point) -> Point:
    """严格校验一个仿射点：类型 → 域 → 曲线方程，错误消息带参数名。"""
    if point is INFINITY:
        # 调用方决定是否允许无穷远；此 helper 只服务“必须有限”的位置。
        from ._errors import PointAtInfinityError

        raise PointAtInfinityError(f"参数 {name!r} 是无穷远点，此处要求有限点")
    if not isinstance(point, tuple) or len(point) != 2:
        raise TypeValidationError(
            f"参数 {name!r} 必须是长度为 2 的 tuple (x, y) 或 None（无穷远），"
            f"收到 {type(point).__name__}: {point!r}"
        )
    x, y = point
    _check_coordinate(f"{name}.x", x)
    _check_coordinate(f"{name}.y", y)
    if (y * y - (x * x * x + COEFF_A * x + COEFF_B)) % FIELD_PRIME != 0:
        raise PointNotOnCurveError(
            f"点 {name}={point!r} 不在曲线 y² = x³+{COEFF_A}x+{COEFF_B} mod {FIELD_PRIME} 上"
        )
    return point


def _validate_any_point(name: str, point):
    """无穷远放行；有限点做完整校验。"""
    if point is INFINITY:
        return INFINITY
    return _validate_finite_point(name, point)


def _validate_scalar(name: str, k) -> int:
    """群标量的统一范围契约：模 19 的规范代表元 0..18。"""
    _reject_nonint(name, k)
    if not 0 <= k < GROUP_ORDER:
        raise ScalarOutOfRangeError(
            f"标量 {name}={k} 超出规范范围 0..{GROUP_ORDER - 1}（不做隐式模 19 约化）"
        )
    return k


def point_neg(point):
    """返回点的逆元（负点）：-O = O，-(x, y) = (x, -y mod 17)。"""
    if point is INFINITY:
        return INFINITY
    x, y = _validate_finite_point("point", point)
    return (x, (-y) % FIELD_PRIME)


def point_add(p, q):
    """椭圆曲线群加法（含无穷远单位元、互逆点与倍点情形）。

    严格校验两个输入点。返回 :data:`INFINITY` 表示结果为无穷远点
    （单位元吸收，或 P + (-P)）。
    """
    p = _validate_any_point("p", p)
    q = _validate_any_point("q", q)

    global _POINT_ADD_CALLS
    _POINT_ADD_CALLS += 1

    if p is INFINITY:
        return q
    if q is INFINITY:
        return p

    x1, y1 = p
    x2, y2 = q

    if x1 == x2:
        if y1 != y2:
            # 互逆点：P + (-P) = O
            return INFINITY
        # 倍点切线：λ = (3x² + a) / (2y)
        numerator = (3 * x1 * x1 + COEFF_A) % FIELD_PRIME
        denominator = (2 * y1) % FIELD_PRIME
        if denominator == 0:
            # y=0 处切线垂直（本曲线上不存在这样的仿射点，仍按群定律返回 O）
            return INFINITY
        lam = (numerator * pow(denominator, -1, FIELD_PRIME)) % FIELD_PRIME
    else:
        # 割线：λ = (y2 - y1) / (x2 - x1)
        numerator = (y2 - y1) % FIELD_PRIME
        denominator = (x2 - x1) % FIELD_PRIME
        lam = (numerator * pow(denominator, -1, FIELD_PRIME)) % FIELD_PRIME

    x3 = (lam * lam - x1 - x2) % FIELD_PRIME
    y3 = (lam * (x1 - x3) - y1) % FIELD_PRIME
    return (x3, y3)


def scalar_mul(k, point):
    """标量乘法 k·P，``k`` 必须是 0..18 的整数（不做隐式约化）。

    采用双加（double-and-add）算法；``k=0`` 返回 :data:`INFINITY`。
    点参数先经过完整校验。
    """
    k = _validate_scalar("k", k)
    point = _validate_any_point("point", point)

    result = INFINITY
    addend = point
    n = k
    while n:
        if n & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        n >>= 1
    return result
