"""教学用 Schnorr 批验签（仅教学，不安全）。

流程（严格、不静默纠正）：
  1. 逐项严格解码并校验：消息类型/长度、R 与 P 必须是曲线上的有限点、
     s ∈ 0..18；任何一项非法即整批拒绝，抛 :class:`BatchItemError`
     （`.index` 给出 0 基输入序号）。
  2. 调用方显式提供与批等长的非零域系数 a_i ∈ 1..18（不允许全 1 以外的
     隐式默认，也不允许 0——0 会把对应项从聚合等式里抹掉）。
  3. 聚合等式（确定性、按输入序左到右求和）：
         (Σ a_i·s_i)·G  ==  Σ a_i·R_i + Σ (a_i·e_i)·P_i
  4. `exact=True` 时用共享倍点表逐项确认，返回按输入序的无效索引。

.. warning::
   **聚合等式通过 ≠ 逐项全部有效。** 小群上错误签名可以相互抵消
   （δ_1·a_1 + δ_2·a_2 ≡ 0 mod 19），聚合通过不能作为安全结论；
   只有 exact 模式的逐项结果才能判定“全部有效”。本模块仅用于教学。

缓存策略：模块级缓存只保存**公开点的倍数表**（G 与出现过的公钥/承诺点
的 0..18 倍），不缓存任何消息质询 e——e 每次都由消息现场重算，
不会跨输入误复用。可用 :func:`clear_multiples_cache` 清空。
"""

from dataclasses import dataclass

from ._errors import (
    BatchItemError,
    InvalidCoefficientError,
    TypeValidationError,
)
from ._curve import (
    GROUP_ORDER,
    GENERATOR,
    Point,
    INFINITY,
    point_add,
    scalar_mul,
    _reject_nonint,
)
from ._encoding import decode_point, decode_scalar
from ._schnorr import (
    _validate_message,
    _require_finite_curve_point,
    challenge,
)

#: 批长度上限（接口边界；教学场景远远够用）。
MAX_BATCH_ITEMS = 4096

#: 模块级公开点倍数缓存：point -> (0·P, 1·P, ..., 18·P)。
#: 只存公开点（G、公钥、承诺 R）的倍数，绝不存消息或质询。
_MULTIPLES_CACHE: dict = {}


def _build_table(point) -> tuple:
    """确定性累加建 0..18 倍表（18 次 point_add，不用双加）。"""
    table = [INFINITY]
    acc = INFINITY
    for _ in range(GROUP_ORDER - 1):
        acc = point_add(acc, point)
        table.append(acc)
    return tuple(table)


#: 基点 G 的倍点表是公开常量，模块导入时一次性构建。
_G_TABLE = _build_table(GENERATOR)


def clear_multiples_cache() -> None:
    """清空公开点倍数缓存（不影响正确性，只影响下次重建表的开销）。"""
    _MULTIPLES_CACHE.clear()


def _multiples(point: Point) -> tuple:
    """返回点的 0..18 倍表；命中缓存则直接复用，否则确定性累加建表。

    建表用 18 次 point_add 逐项累加（不用双加），保证确定性且便于计数。
    """
    cached = _MULTIPLES_CACHE.get(point)
    if cached is not None:
        return cached
    if point == GENERATOR:
        return _G_TABLE
    result = _build_table(point)
    _MULTIPLES_CACHE[point] = result
    return result


@dataclass(frozen=True)
class BatchEntry:
    """批中一项：消息、公钥与签名 (R, s)。构造时只做形状约束，
    完整曲线校验在 :func:`batch_verify` 内逐项进行。"""

    message: bytes
    public_key: Point
    r: Point
    s: int


@dataclass(frozen=True)
class BatchReport:
    """批验签报告。

    - `aggregate_ok`：加权聚合等式是否成立（**不代表逐项有效**）；
    - `exact`：是否执行了逐项确认；
    - `all_valid`：仅 exact 模式给出 True/False，否则为 None；
    - `invalid_indices`：exact 模式下按输入序的无效项 0 基索引，
      非 exact 模式为 None。
    """

    item_count: int
    aggregate_ok: bool
    exact: bool
    all_valid: bool | None
    invalid_indices: tuple | None = None


def _validate_coefficients(coefficients, count: int) -> tuple:
    if isinstance(coefficients, (bytes, bytearray, str)) or not hasattr(
        coefficients, "__iter__"
    ):
        raise TypeValidationError(
            f"coefficients 必须是整数序列，收到 {type(coefficients).__name__}"
        )
    coeffs = tuple(coefficients)
    if len(coeffs) != count:
        raise InvalidCoefficientError(
            f"coefficients 数量 {len(coeffs)} 与批长度 {count} 不一致"
        )
    for i, a in enumerate(coeffs):
        try:
            _reject_nonint(f"coefficients[{i}]", a)
        except TypeValidationError as exc:
            raise InvalidCoefficientError(str(exc)) from exc
        if not 1 <= a < GROUP_ORDER:
            raise InvalidCoefficientError(
                f"coefficients[{i}]={a} 必须是 1..{GROUP_ORDER - 1} 的非零域元素"
                "（0 会把对应项从聚合等式中抹掉，禁止）"
            )
    return coeffs


def _validate_entry(index: int, entry) -> tuple:
    """逐项严格校验，返回 (message, public_key, r, s)；非法抛 BatchItemError。"""
    try:
        if not isinstance(entry, BatchEntry):
            raise TypeValidationError(
                f"批项必须是 BatchEntry，收到 {type(entry).__name__}"
            )
        msg = _validate_message(entry.message)
        public_key = _require_finite_curve_point("public_key", entry.public_key)
        r = _require_finite_curve_point("r", entry.r)
        _reject_nonint("s", entry.s)
        if not 0 <= entry.s < GROUP_ORDER:
            from ._errors import ScalarOutOfRangeError

            raise ScalarOutOfRangeError(
                f"s={entry.s} 超出规范范围 0..{GROUP_ORDER - 1}"
            )
        return msg, public_key, r, entry.s
    except BatchItemError:
        raise
    except Exception as exc:
        raise BatchItemError(index, str(exc)) from exc


def _decode_entry(index: int, entry) -> tuple:
    """编码入口的逐项严格解码，返回 (message, public_key, r, s)。"""
    try:
        message, public_key_enc, r_enc, s_enc = entry
    except Exception as exc:
        raise BatchItemError(
            index, f"编码批项必须是 (message, public_key_enc, r_enc, s_enc) 四元组：{exc}"
        ) from exc
    try:
        msg = _validate_message(message)
        public_key = decode_point(public_key_enc, allow_infinity=False)
        r = decode_point(r_enc, allow_infinity=False)
        s = decode_scalar(s_enc, name="s")
        return msg, public_key, r, s
    except BatchItemError:
        raise
    except Exception as exc:
        raise BatchItemError(index, str(exc)) from exc


def _aggregate_ok(items: list, coeffs: tuple, challenges: list) -> bool:
    """确定性聚合：左端合成单个标量，右端按输入序用倍点表累加。"""
    g_table = _multiples(GENERATOR)
    lhs_scalar = 0
    rhs = INFINITY
    for (msg, public_key, r, s), a, e in zip(items, coeffs, challenges):
        lhs_scalar = (lhs_scalar + a * s) % GROUP_ORDER
        # R 每项一般只出现一次，建 19 倍表不划算：用确定性双加标量乘。
        rhs = point_add(rhs, scalar_mul(a, r))
        rhs = point_add(rhs, _multiples(public_key)[(a * e) % GROUP_ORDER])
    return g_table[lhs_scalar] == rhs


def _bisect_order(items: list, coeffs: tuple, challenges: list) -> list:
    """聚合失败时二分缩小候选，返回**检查顺序**（候选子组优先）。

    注意：聚合通过的子组也可能藏有相互抵消的错误，因此该顺序只影响
    exact 逐项检查的发现先后，**不能**用来跳过任何子组。
    """
    order = []

    def visit(indices):
        if not indices:
            return
        g_table = _multiples(GENERATOR)
        lhs_scalar = 0
        rhs = INFINITY
        for i in indices:
            msg, public_key, r, s = items[i]
            a = coeffs[i]
            lhs_scalar = (lhs_scalar + a * s) % GROUP_ORDER
            rhs = point_add(rhs, scalar_mul(a, r))
            rhs = point_add(rhs, _multiples(public_key)[(a * challenges[i]) % GROUP_ORDER])
        if g_table[lhs_scalar] == rhs:
            # 子组聚合通过：仍可能藏抵消，排在后面但**必须**检查。
            order.extend(indices)
            return
        if len(indices) == 1:
            order.extend(indices)
            return
        mid = len(indices) // 2
        visit(indices[:mid])
        visit(indices[mid:])

    visit(list(range(len(items))))
    return order


def _exact_invalid_indices(items: list, coeffs: tuple, challenges: list,
                           aggregate_ok: bool) -> tuple:
    """用共享倍点表逐项确认；返回按输入序的无效索引。

    聚合失败时先用二分确定检查顺序（候选优先），但**每一项都会被
    单独检查**——聚合通过的子组不允许跳过。
    """
    g_table = _multiples(GENERATOR)
    if items and not aggregate_ok:
        check_order = _bisect_order(items, coeffs, challenges)
    else:
        check_order = list(range(len(items)))
    invalid = []
    for i in check_order:
        msg, public_key, r, s = items[i]
        lhs = g_table[s]
        rhs = point_add(r, _multiples(public_key)[challenges[i]])
        if lhs != rhs:
            invalid.append(i)
    return tuple(sorted(invalid))


def _run_batch(items: list, coefficients, exact: bool) -> BatchReport:
    count = len(items)
    if count > MAX_BATCH_ITEMS:
        raise BatchItemError(
            MAX_BATCH_ITEMS,
            f"批长度 {count} 超过上限 MAX_BATCH_ITEMS={MAX_BATCH_ITEMS}",
        )
    coeffs = _validate_coefficients(coefficients, count)
    # 空批：空和恒等成立，聚合等式通过；exact 下“全部有效” vacuously 为真。
    challenges = [challenge(r, public_key, msg) for msg, public_key, r, s in items]
    aggregate_ok = _aggregate_ok(items, coeffs, challenges)
    if not exact:
        return BatchReport(
            item_count=count,
            aggregate_ok=aggregate_ok,
            exact=False,
            all_valid=None,
            invalid_indices=None,
        )
    invalid = _exact_invalid_indices(items, coeffs, challenges, aggregate_ok)
    return BatchReport(
        item_count=count,
        aggregate_ok=aggregate_ok,
        exact=True,
        all_valid=not invalid,
        invalid_indices=invalid,
    )


def batch_verify(entries, coefficients, *, exact: bool = False) -> BatchReport:
    """教学批验签（点对象入口）。

    `entries` 为 :class:`BatchEntry` 序列；`coefficients` 为调用方
    提供的等长非零域系数（1..18）。先逐项严格校验，再检查加权聚合等式；
    `exact=True` 时逐项确认并给出按输入序的无效索引。

    任何一项结构非法即整批拒绝（:class:`BatchItemError`，含索引），
    不存在“部分验签”。
    """
    if not isinstance(exact, bool):
        raise TypeValidationError(f"exact 必须是 bool，收到 {type(exact).__name__}")
    entries = tuple(entries)
    items = [_validate_entry(i, entry) for i, entry in enumerate(entries)]
    return _run_batch(items, coefficients, exact)


def batch_verify_encoded(encoded_entries, coefficients, *, exact: bool = False) -> BatchReport:
    """教学批验签（编码入口）。

    每项为 `(message, public_key_enc, r_enc, s_enc)`：压缩点编码与
    1 字节标量编码，按严格规则解码（拒绝无穷远、非最短、域外编码）。
    任一编码非法即整批拒绝，:class:`BatchItemError` 携带 0 基索引。
    """
    if not isinstance(exact, bool):
        raise TypeValidationError(f"exact 必须是 bool，收到 {type(exact).__name__}")
    encoded_entries = tuple(encoded_entries)
    items = [_decode_entry(i, entry) for i, entry in enumerate(encoded_entries)]
    return _run_batch(items, coefficients, exact)
