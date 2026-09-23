"""独立参考实现（仅供测试）。

本模块**绝不 import ec17**，被测核心的期望值全部由这里独立给出。
它刻意采用与核心不同的两条路线，互相也独立：

1. 朴素仿射公式 ``aff_add`` / ``aff_mul``：直接展开斜率公式，
   乘法用“重复相加”循环，不用双加算法；
2. 离散对数指数表 ``exp_add`` / ``exp_mul``：先用朴素公式枚举 G 的
   所有倍数，建立点 <-> 指数双向表，之后群运算完全退化为指数的
   整数加法——这一条根本不接触任何斜率公式。

枚举/平方根恢复都基于对 0..16 的穷举（域只有 17 个元素）。
"""

import hashlib

P_MOD = 17
A_COEF = 2
B_COEF = 2
ORDER = 19
G_POINT = (5, 1)
O = None  # 无穷远点


def finite_points():
    """穷举 F_17 x F_17，返回全部满足曲线方程的点。"""
    found = []
    for x in range(P_MOD):
        for y in range(P_MOD):
            if (y * y - (x * x * x + A_COEF * x + B_COEF)) % P_MOD == 0:
                found.append((x, y))
    return found


def aff_add(p, q):
    """路线 1：朴素仿射加法（独立于核心的写法，无公共 helper）。"""
    if p is O:
        return q
    if q is O:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P_MOD == 0:
            return O
        top = (3 * x1 * x1 + A_COEF) % P_MOD
        bot = (2 * y1) % P_MOD
        slope = (top * pow(bot, P_MOD - 2, P_MOD)) % P_MOD
    else:
        top = (y2 - y1) % P_MOD
        bot = (x2 - x1) % P_MOD
        slope = (top * pow(bot, P_MOD - 2, P_MOD)) % P_MOD
    x3 = (slope * slope - x1 - x2) % P_MOD
    y3 = (-y1 + slope * (x1 - x3)) % P_MOD
    return (x3, y3)


def aff_mul(k, point):
    """k 次重复相加（允许 k>=19，用于独立核对 19G=O）。"""
    if k < 0:
        raise ValueError("reference: negative k not supported")
    total = O
    for _ in range(k):
        total = aff_add(total, point)
    return total


def aff_neg(point):
    if point is O:
        return O
    x, y = point
    return (x, (P_MOD - y) % P_MOD)


# 路线 2：以枚举倍数构造指数表 ---------------------------------------------

_EXP = [O]
_CUR = O
for _i in range(1, ORDER):
    _CUR = aff_add(_CUR, G_POINT)
    _EXP.append(_CUR)
# _EXP[i] = i*G（i=0 为 O）
_LOG = {pt: i for i, pt in enumerate(_EXP) if pt is not None}


def exp_table():
    """返回 (倍数表, 离散对数表) 的副本。"""
    return list(_EXP), dict(_LOG)


def exp_add(p, q):
    if p is O:
        return q
    if q is O:
        return p
    return _EXP[(_LOG[p] + _LOG[q]) % ORDER]


def exp_neg(p):
    if p is O:
        return O
    return _EXP[(-_LOG[p]) % ORDER]


def exp_mul(k, p):
    """指数路线的标量乘法：k*(i*G) = (k*i mod 19)*G。"""
    if p is O:
        return O
    return _EXP[(k * _LOG[p]) % ORDER]


# 独立的压缩编码 -----------------------------------------------------------


def ref_encode_point(point):
    if point is O:
        return b"\x00"
    x, y = point
    return bytes((0x02 if y % 2 == 0 else 0x03, x))


def ref_sqrt_candidates(x):
    """返回 x³+ax+b 在 F_17 上的全部平方根（0、1 或 2 个）。"""
    rhs = (x * x * x + A_COEF * x + B_COEF) % P_MOD
    return [y for y in range(P_MOD) if (y * y) % P_MOD == rhs]


def ref_challenge(r_point, pub, message):
    blob = ref_encode_point(r_point) + ref_encode_point(pub) + bytes(message)
    return int.from_bytes(hashlib.sha256(blob).digest(), "big") % ORDER


def ref_sign(secret_key, message, nonce):
    """独立 Schnorr 签名，返回 (P, R, e, s) 四元组。"""
    pub = aff_mul(secret_key, G_POINT)
    r_point = aff_mul(nonce, G_POINT)
    e_val = ref_challenge(r_point, pub, message)
    s_val = (nonce + e_val * secret_key) % ORDER
    return pub, r_point, e_val, s_val


def ref_verify(message, pub, r_point, s_val):
    e_val = ref_challenge(r_point, pub, message)
    return aff_mul(s_val, G_POINT) == aff_add(r_point, aff_mul(e_val, pub))
