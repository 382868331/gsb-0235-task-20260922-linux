"""教学批验签（仅教学，不安全）。

在现有严格验签数据流上扩展“聚合 + 可选逐项”的批验签：

1. 先逐项严格校验（消息类型/长度、R/P 为曲线上有限点、s ∈ 0..18），
   编码入口再先做严格解码；任何一项非法即整批拒绝，错误携带下标；
2. 调用方显式提供非零域系数 a_i ∈ 1..18（禁止 0，防止“跳过某项”）；
3. 聚合等式：  (Σ a_i·s_i)·G == Σ a_i·R_i + Σ (a_i·e_i)·P_i，
   其中 e_i = SHA256(encode(R_i) ∥ encode(P_i) ∥ message_i) mod 19 逐项重算，
   绝不跨输入复用消息挑战；
4. 报告严格区分 ``aggregate_ok``（加权等式成立）与 ``all_valid``（逐项全部
   有效）。小群上错误签名的缺陷可能相互抵消，**aggregate_ok=True 不是
   安全结论**；只有 exact 模式逐项确认后的 ``all_valid`` 才可作为逐项结论。

exact 模式使用共享倍点表（G 与每个不同公钥 P 的 0..18 倍表，只缓存公开点
的倍数）做确定性的逐项检查，按输入序返回无效下标；聚合失败的批次可用
:func:`bisect_aggregate_candidates` 二分缩小候选，但聚合通过的子组也可能
藏有抵消，二分结果只是候选，不能替代 exact。

空批合法：聚合等式 O == O 成立，逐项集合为空（vacuously 全部有效）。
"""

from dataclasses import dataclass

from ._errors import (
    EC17Error,
    BatchLengthMismatchError,
    BatchTooLargeError,
    InvalidCoefficientError,
    BatchItemError,
    TypeValidationError,
    ScalarOutOfRangeError,
)
from ._curve import (
    GROUP_ORDER,
    GENERATOR,
    INFINITY,
    Point,
    point_add,
    _reject_nonint,
)
from ._schnorr import _validate_message, challenge
from ._encoding import decode_point, decode_scalar

#: 批大小上限（接口边界；曲线极小，该值纯属防御性限制）。
MAX_BATCH_SIZE = 4096


@dataclass(frozen=True)
class BatchEntry:
    """一条待批验签的记录（解码后的内部形态）。字段只读。"""

    message: bytes
    public_key: Point
    r: Point
    s: int


@dataclass(frozen=True)
class BatchReport:
    """批验签报告。

    - ``aggregate_ok``：加权聚合等式是否成立（**不是安全结论**）；
    - ``all_valid``：逐项全部有效；非 exact 模式为 ``None``（未知）；
    - ``invalid_indices``：exact 模式按输入序的无效下标，否则为 ``None``；
    - ``point_additions``：本次批验签实际执行的群加法次数（供教学对比）。
    """

    size: int
    aggregate_ok: bool
    exact: bool
    all_valid: object  # bool | None
    invalid_indices: object  # tuple[int, ...] | None
    point_additions: int


class _AddCounter:
    """群加法计数器（教学度量，随报告返回）。"""

    def __init__(self):
        self.count = 0

    def add(self, p, q):
        self.count += 1
        return point_add(p, q)

    def mul(self, k, point):
        """计数版双加标量乘（用于不建表的 R 点加权）。"""
        result = INFINITY
        addend = point
        n = k
        while n:
            if n & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            n >>= 1
        return result


def _build_table(point, counter):
    """公开点的共享倍点表：table[k] = k·point（k ∈ 0..18），重复相加构造。"""
    table = [INFINITY] * GROUP_ORDER
    acc = INFINITY
    for k in range(1, GROUP_ORDER):
        acc = counter.add(acc, point)
        table[k] = acc
    return table


def _validate_coefficients(coefficients, size):
    if isinstance(coefficients, (bytes, bytearray, str)) or not isinstance(
        coefficients, (list, tuple)
    ):
        raise TypeValidationError(
            f"coefficients 必须是 int 的 list/tuple，收到 {type(coefficients).__name__}"
        )
    if len(coefficients) != size:
        raise BatchLengthMismatchError(
            f"coefficients 长度 {len(coefficients)} 与批大小 {size} 不一致"
        )
    coeffs = []
    for i, a in enumerate(coefficients):
        _reject_nonint(f"coefficients[{i}]", a)
        if not 0 <= a < GROUP_ORDER:
            raise InvalidCoefficientError(
                f"coefficients[{i}]={a} 超出域 Z_{GROUP_ORDER}（要求 1..{GROUP_ORDER - 1}）"
            )
        if a == 0:
            raise InvalidCoefficientError(
                f"coefficients[{i}]=0 被禁止：零系数会把第 {i} 项从聚合等式中静默剔除"
            )
        coeffs.append(a)
    return coeffs


def _normalize_entries(entries):
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(
        entries, (list, tuple)
    ):
        raise TypeValidationError(
            f"entries 必须是 BatchEntry/四元组 的 list/tuple，收到 {type(entries).__name__}"
        )
    if len(entries) > MAX_BATCH_SIZE:
        raise BatchTooLargeError(
            f"批大小 {len(entries)} 超过上限 MAX_BATCH_SIZE={MAX_BATCH_SIZE}"
        )
    normalized = []
    for i, item in enumerate(entries):
        try:
            if isinstance(item, BatchEntry):
                entry = item
            elif isinstance(item, tuple) and len(item) == 4:
                entry = BatchEntry(*item)
            else:
                raise TypeValidationError(
                    f"批项必须是 BatchEntry 或 (message, public_key, r, s) 四元组，"
                    f"收到 {type(item).__name__}"
                )
            msg = _validate_message(entry.message)
            if entry.public_key is None:
                from ._errors import PointAtInfinityError

                raise PointAtInfinityError("public_key 是无穷远点，验签要求有限点")
            if entry.r is None:
                from ._errors import PointAtInfinityError

                raise PointAtInfinityError("r 是无穷远点，验签要求有限点")
            from ._curve import _validate_finite_point

            public_key = _validate_finite_point("public_key", entry.public_key)
            r_point = _validate_finite_point("r", entry.r)
            _reject_nonint("s", entry.s)
            if not 0 <= entry.s < GROUP_ORDER:
                raise ScalarOutOfRangeError(
                    f"s={entry.s} 超出规范范围 0..{GROUP_ORDER - 1}"
                )
            normalized.append((msg, public_key, r_point, entry.s))
        except EC17Error as exc:
            raise BatchItemError(i, f"{type(exc).__name__}: {exc}") from exc
    return normalized


def _challenges(normalized):
    """逐项重算消息挑战（绝不缓存/跨输入复用）。"""
    return [challenge(r, p, m) for (m, p, r, _s) in normalized]


def _aggregate(normalized, coeffs, challenges, counter, tables):
    """确定性多标量聚合：G 与公钥查共享倍点表，R 用计数双加，固定顺序求和。"""
    g_scalar = 0
    pub_scalars = {}
    rhs = INFINITY
    for (msg, public_key, r_point, s), a, e in zip(normalized, coeffs, challenges):
        g_scalar = (g_scalar + a * s) % GROUP_ORDER
        pub_scalars[public_key] = (pub_scalars.get(public_key, 0) + a * e) % GROUP_ORDER
        # R 每项唯一，建表不摊销，直接计数双加。
        rhs = counter.add(rhs, counter.mul(a, r_point))

    lhs = tables[GENERATOR][g_scalar]
    # 公钥按输入首次出现顺序求和，保证确定性。
    for point, scalar in pub_scalars.items():
        if scalar == 0:
            continue
        rhs = counter.add(rhs, tables[point][scalar])
    return lhs == rhs


def _exact_check(normalized, challenges, counter, tables):
    """逐项确认：s·G == R + e·P，全部查共享倍点表，按输入序返回无效下标。"""
    g_table = tables[GENERATOR]
    invalid = []
    for i, ((msg, public_key, r_point, s), e) in enumerate(zip(normalized, challenges)):
        lhs = g_table[s]
        rhs = counter.add(r_point, tables[public_key][e])
        if lhs != rhs:
            invalid.append(i)
    return tuple(invalid)


def _prepare_tables(normalized, counter):
    """共享倍点表缓存：只存公开点（G 与公钥 P）的倍数，按首次出现去重。

    消息挑战 e 永不缓存；R 点每项唯一，不建表（见 _aggregate）。
    """
    tables = {}
    tables[GENERATOR] = _build_table(GENERATOR, counter)
    for _msg, public_key, r_point, _s in normalized:
        if public_key not in tables:
            tables[public_key] = _build_table(public_key, counter)
    return tables


def batch_verify(entries, coefficients, *, exact=False) -> BatchReport:
    """教学批验签。

    ``entries`` 为 :class:`BatchEntry` 或 ``(message, public_key, r, s)`` 四元组
    的序列；``coefficients`` 为等长的非零域系数（1..18）。

    任何一项结构非法（点/标量/消息不合法）即整批拒绝并抛
    :class:`BatchItemError`（``error.index`` 给出下标），不存在部分通过。
    空批合法。
    """
    if not isinstance(exact, bool):
        raise TypeValidationError(f"exact 必须是 bool，收到 {type(exact).__name__}")
    normalized = _normalize_entries(entries)
    coeffs = _validate_coefficients(coefficients, len(normalized))

    counter = _AddCounter()
    size = len(normalized)
    if size == 0:
        return BatchReport(
            size=0,
            aggregate_ok=True,
            exact=exact,
            all_valid=True,
            invalid_indices=(),
            point_additions=0,
        )

    challenges = _challenges(normalized)
    tables = _prepare_tables(normalized, counter)
    aggregate_ok = _aggregate(normalized, coeffs, challenges, counter, tables)

    if exact:
        invalid = _exact_check(normalized, challenges, counter, tables)
        all_valid = not invalid
    else:
        invalid = None
        all_valid = None
    return BatchReport(
        size=size,
        aggregate_ok=aggregate_ok,
        exact=exact,
        all_valid=all_valid,
        invalid_indices=invalid,
        point_additions=counter.count,
    )


def batch_verify_encoded(encoded_entries, coefficients, *, exact=False) -> BatchReport:
    """编码入口的批验签：先逐项严格解码，非法编码整批拒绝并给出下标。

    每项为 ``(message, public_key_enc, r_enc, s_enc)``：压缩点编码（2 字节）、
    压缩点编码（2 字节）、1 字节标量；解码规则与单条验签完全一致
    （拒绝无穷远、非最短与域外编码）。
    """
    if isinstance(encoded_entries, (bytes, bytearray, str)) or not isinstance(
        encoded_entries, (list, tuple)
    ):
        raise TypeValidationError(
            f"encoded_entries 必须是四元组的 list/tuple，收到 {type(encoded_entries).__name__}"
        )
    decoded = []
    for i, item in enumerate(encoded_entries):
        try:
            if not (isinstance(item, tuple) and len(item) == 4):
                raise TypeValidationError(
                    f"编码批项必须是 (message, public_key_enc, r_enc, s_enc) 四元组，"
                    f"收到 {type(item).__name__}"
                )
            message, public_key_enc, r_enc, s_enc = item
            msg = _validate_message(message)
            public_key = decode_point(public_key_enc, allow_infinity=False)
            r_point = decode_point(r_enc, allow_infinity=False)
            s_value = decode_scalar(s_enc, name="s")
            decoded.append(BatchEntry(msg, public_key, r_point, s_value))
        except EC17Error as exc:
            raise BatchItemError(i, f"{type(exc).__name__}: {exc}") from exc
    return batch_verify(decoded, coefficients, exact=exact)


def bisect_aggregate_candidates(entries, coefficients) -> tuple:
    """聚合失败批次的二分候选定位（**只是候选，不是逐项结论**）。

    递归地把聚合仍失败的子批二分；聚合通过的子组被标记为“候选清除”，
    但小群上通过聚合的子组也可能藏有相互抵消的无效项——确认必须用
    ``batch_verify(..., exact=True)``。返回按输入序的候选下标。
    """
    normalized = _normalize_entries(entries)
    coeffs = _validate_coefficients(coefficients, len(normalized))
    size = len(normalized)
    if size == 0:
        return ()

    def aggregate_ok_slice(idxs):
        sub = [normalized[i] for i in idxs]
        sub_coeffs = [coeffs[i] for i in idxs]
        counter = _AddCounter()
        challenges = _challenges(sub)
        tables = _prepare_tables(sub, counter)
        return _aggregate(sub, sub_coeffs, challenges, counter, tables)

    if aggregate_ok_slice(list(range(size))):
        return ()

    candidates = []

    def recurse(idxs):
        if len(idxs) == 1:
            candidates.append(idxs[0])
            return
        mid = len(idxs) // 2
        left, right = idxs[:mid], idxs[mid:]
        # 两侧都查：一侧聚合通过不能证明另一侧之外的项有效，
        # 但本函数只对“聚合仍失败”的子组继续二分（候选语义，见 docstring）。
        left_ok = aggregate_ok_slice(left)
        right_ok = aggregate_ok_slice(right)
        if left_ok and right_ok:
            # 抵消发生在跨半之间，二分无法继续缩小：整组都是候选。
            candidates.extend(idxs)
            return
        if not left_ok:
            recurse(left)
        if not right_ok:
            recurse(right)

    recurse(list(range(size)))
    return tuple(sorted(candidates))
