"""独立参考实现 —— 不导入、不调用被测核心 ``ecc_teach``。

本文件只用题目原文给出的常量（p=17, a=2, b=2, G=(5,1), n=19）重新推导：

1. 暴力枚举 F_17 上全部曲线点（含用 ``None`` 表示的无穷远点 O）；
2. 直接按教材公式独立实现点加/倍点/标量乘，构造完整 19×19 加法表；
3. 在加法表上**穷举**验证群公理（封闭、同一、逆元唯一、结合、交换），
   并验证由 G 生成的循环子群恰为全群、G 的阶恰为 19；
4. 提供独立的压缩编码解码（自己枚举 y）与独立 Schnorr 验签，
   供测试把它的结论与被测实现交叉比对。

期望值得自这里的独立枚举/公式，绝不从 ``ecc_teach`` 读出后再比较；
往返一致性（encode→decode）在测试里只能作为补充断言。
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

# 题目原文常量；与 ecc_teach 的常量字面值相同，但此处刻意独立定义。
P = 17
A = 2
B = 2
N = 19
GX, GY = 5, 1

Pt = Optional[Tuple[int, int]]  # None = 无穷远点 O


# ---------------------------------------------------------------------------
# 独立的曲线枚举与群运算
# ---------------------------------------------------------------------------


def _on_curve(x: int, y: int) -> bool:
    return (y * y - (x * x * x + A * x + B)) % P == 0


def all_affine_points() -> List[Tuple[int, int]]:
    """暴力枚举 0<=x,y<17，列出全部仿射曲线点（按 (x,y) 排序）。"""
    return [(x, y) for x in range(P) for y in range(P) if _on_curve(x, y)]


def _inv(z: int) -> int:
    return pow(z % P, -1, P)


def ref_add(u: Pt, v: Pt) -> Pt:
    """教材显式公式的独立实现（与被测代码风格刻意不同：扁平分支）。"""
    if u is None:
        return v
    if v is None:
        return u
    x1, y1 = u
    x2, y2 = v
    if x1 == x2:
        if y1 != y2:  # y2 == -y1 => O（二次根最多两个）
            return None
        slope = ((3 * x1 * x1 + A) * _inv(2 * y1)) % P
    else:
        slope = ((y2 - y1) * _inv(x2 - x1)) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def ref_mul(k: int, point: Pt) -> Pt:
    """独立标量乘：右到左二进制，调用 ref_add。k 按模 N 先归约。"""
    k %= N
    out: Pt = None
    base: Pt = point
    while k:
        if k & 1:
            out = ref_add(out, base)
        base = ref_add(base, base)
        k >>= 1
    return out


def build_group() -> Tuple[List[Pt], Dict[Tuple[Pt, Pt], Pt], Dict[Pt, int]]:
    """返回 (群元素表, 加法表, 点->以G为底的离散对数表)。

    群元素表按离散对数 0..18 排列：elements[0]=O, elements[1]=G, ...
    加法表 add_table[(i*形式的点, j*形式的点)] 给出和点。
    """
    elements: List[Pt] = [None]
    cur: Pt = None
    for _ in range(1, N):
        cur = ref_add(cur, (GX, GY))
        elements.append(cur)

    add_table: Dict[Tuple[Pt, Pt], Pt] = {}
    for q_i in elements:
        for q_j in elements:
            add_table[(q_i, q_j)] = ref_add(q_i, q_j)

    dlog: Dict[Pt, int] = {point: i for i, point in enumerate(elements)}
    return elements, add_table, dlog


# ---------------------------------------------------------------------------
# 穷举群公理验证（测试直接调用并断言无异常）
# ---------------------------------------------------------------------------


def exhaustive_group_checks() -> List[str]:
    """对完整群表穷举验证群公理，返回逐条通过的说明（失败则 AssertionError）。"""
    affine = all_affine_points()
    elements, table, dlog = build_group()
    notes: List[str] = []

    # (1) 枚举点数量：18 仿射 + O = 19。
    assert len(affine) == N - 1, f"仿射点数应为 18，实际 {len(affine)}"
    assert len(elements) == N
    assert len(set(elements)) == N, "G 的倍数出现重复，阶不为 19"
    notes.append("枚举得到 18 个仿射点，加无穷远点共 19 个群元素")

    # (2) 枚举点集合 == G 生成的点集合（循环群覆盖全曲线点集）。
    assert set(elements) == set(affine) | {None}
    notes.append("G 的 0..18 倍点恰好无重复地覆盖全部 19 个点 => G 阶为 19")

    # (3) 封闭性：表中每项都在元素集合内。
    for w in table.values():
        assert w is None or w in set(affine)
    notes.append("19×19 加法表全部落在群元素集合内（封闭性）")

    # (4) 同一律：O+Q=Q+O=Q。
    for q in elements:
        assert table[(None, q)] == q and table[(q, None)] == q
    notes.append("穷举同一律 O+Q=Q+O=Q 成立")

    # (5) 逆元存在且唯一：对每个 Q 恰好存在一个 R 使 Q+R=O，且 R=-Q 坐标一致。
    for q in elements:
        inverses = [r for r in elements if table[(q, r)] is None]
        assert len(inverses) == 1
        r = inverses[0]
        if q is None:
            assert r is None
        else:
            qx, qy = q
            rx, ry = r
            assert rx == qx and ry == (-qy) % P
    notes.append("穷举每个点逆元唯一，且 -(x,y)=(x,-y mod 17)（含 -O=O）")

    # (6) 结合律穷举：(Q+R)+S = Q+(R+S)，19^3 组。
    for q in elements:
        for r in elements:
            qr = table[(q, r)]
            for s in elements:
                assert table[(qr, s)] == table[(q, table[(r, s)])]
    notes.append("穷举 19³ 组结合律 (Q+R)+S=Q+(R+S) 全部成立")

    # (7) 交换律穷举（椭圆曲线群应为 Abel 群）。
    for q in elements:
        for r in elements:
            assert table[(q, r)] == table[(r, q)]
    notes.append("穷举交换律 Q+R=R+Q 全部成立")

    # (8) 加法表与离散对数一致：dlog(Q+R) = dlog(Q)+dlog(R) mod 19。
    for q in elements:
        for r in elements:
            assert dlog[table[(q, r)]] == (dlog[q] + dlog[r]) % N
    notes.append("加法表与离散对数表一致：log(Q+R) ≡ log(Q)+log(R) mod 19")

    # (9) 阶为素数 19 => 每个非单位元都是生成元。
    for q in elements[1:]:
        seen = set()
        cur: Pt = None
        for _ in range(N):
            seen.add(cur)
            cur = ref_add(cur, q)
        assert len(seen) == N and cur is None
    notes.append("每个非单位元的阶都是 19（素数阶群无真子群）")

    return notes


# ---------------------------------------------------------------------------
# 独立压缩编码/解码（自己从字节与枚举出发）
# ---------------------------------------------------------------------------


def ref_encode(point: Pt) -> bytes:
    if point is None:
        return b"\x00"
    x, y = point
    return bytes((0x02 if y % 2 == 0 else 0x03, x))


def ref_decode(data: bytes) -> Pt:
    """独立严格解码；非法输入抛 ValueError。规则直接按契约字面实现。"""
    if not isinstance(data, bytes):
        raise ValueError("编码必须是 bytes")
    if len(data) == 1:
        if data[0] == 0x00:
            return None
        raise ValueError("非法单字节")
    if len(data) != 2:
        raise ValueError("非最短编码")
    prefix, x = data[0], data[1]
    if prefix not in (0x02, 0x03):
        raise ValueError("非法奇偶前缀")
    if not 0 <= x < P:
        raise ValueError("x 域外")
    candidates = [y for y in range(P) if _on_curve(x, y) and y % 2 == (0 if prefix == 0x02 else 1)]
    if len(candidates) != 1:
        raise ValueError("错误奇偶或无点")
    return (x, candidates[0])


# ---------------------------------------------------------------------------
# 独立 Schnorr 验签与合成（仅供测试交叉比对；不接触被测代码）
# ---------------------------------------------------------------------------


def ref_challenge(r_point: Pt, pub_point: Pt, message: bytes) -> int:
    preimage = ref_encode(r_point) + ref_encode(pub_point) + message
    return int.from_bytes(hashlib.sha256(preimage).digest(), "big") % N


def ref_sign(d: int, message: bytes, k: int) -> Tuple[int, bytes]:
    r_point = ref_mul(k, (GX, GY))
    pub = ref_mul(d, (GX, GY))
    e = ref_challenge(r_point, pub, message)
    s = (k + e * d) % N
    return s, ref_encode(r_point)


def ref_verify(pub_enc: bytes, message: bytes, s: int, r_enc: bytes) -> bool:
    """返回布尔；任何非法结构/方程失败均为 False（测试再细查原因）。"""
    if not isinstance(s, int) or isinstance(s, bool) or not 0 <= s < N:
        return False
    try:
        pub = ref_decode(pub_enc)
        r_pt = ref_decode(r_enc)
    except ValueError:
        return False
    if pub is None or r_pt is None:
        return False
    if not isinstance(message, bytes):
        return False
    e = ref_challenge(r_pt, pub, message)
    return ref_mul(s, (GX, GY)) == ref_add(r_pt, ref_mul(e, pub))
