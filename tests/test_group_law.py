"""群律穷举测试：独立参考验证核心群运算。

覆盖：点集基数、G 的阶、单位元（无穷远）、逆点、交换律，
以及 19³ 全三元组结合律；核心结果同时对两条独立路线
（朴素仿射公式 / 离散对数指数表）交叉核对。
"""

import unittest

import ec17
from reference import (
    P_MOD,
    ORDER,
    G_POINT,
    O,
    finite_points,
    aff_add,
    aff_mul,
    aff_neg,
    exp_add,
    exp_mul,
    exp_neg,
    exp_table,
)


FINITE = finite_points()
MULTIPLES, LOG = exp_table()
ALL_POINTS = FINITE + [O]  # 18 个有限点 + 无穷远


class EnumerationTests(unittest.TestCase):
    def test_curve_has_18_finite_points_plus_infinity(self):
        self.assertEqual(len(FINITE), 18)
        self.assertEqual(len(ALL_POINTS), ORDER)

    def test_generates_all_finite_points(self):
        self.assertEqual(sorted(MULTIPLES[1:]), sorted(FINITE))

    def test_order_of_g_is_19(self):
        # 独立朴素重复相加：18G 仍是有限点，19G 恰好回到无穷远。
        self.assertIsNotNone(aff_mul(ORDER - 1, G_POINT))
        self.assertIsNone(aff_mul(ORDER, G_POINT))
        # 核心用逐次 point_add 同样满足 19G = O（而非走标量范围限制）。
        self.assertIsNone(_core_19g())

    def test_every_finite_point_is_core_on_curve(self):
        for pt in FINITE:
            self.assertTrue(ec17.is_on_curve(pt), pt)
        self.assertFalse(ec17.is_on_curve(ec17.INFINITY))


def _core_19g():
    total = ec17.INFINITY
    for _ in range(ORDER):
        total = ec17.point_add(total, ec17.GENERATOR)
    return total


class GroupTableTests(unittest.TestCase):
    def test_addition_table_matches_both_independent_routes(self):
        # 19x19 全加法表：核心 vs 朴素仿射 vs 指数表，三者一致。
        for p in ALL_POINTS:
            for q in ALL_POINTS:
                core = ec17.point_add(p, q)
                via_aff = aff_add(p, q)
                via_exp = exp_add(p, q)
                self.assertEqual(core, via_aff, (p, q))
                self.assertEqual(via_aff, via_exp, (p, q))

    def test_commutativity(self):
        for p in ALL_POINTS:
            for q in ALL_POINTS:
                self.assertEqual(ec17.point_add(p, q), ec17.point_add(q, p))

    def test_infinity_is_identity(self):
        for p in ALL_POINTS:
            self.assertEqual(ec17.point_add(p, ec17.INFINITY), p)
            self.assertEqual(ec17.point_add(ec17.INFINITY, p), p)

    def test_inverse_points(self):
        for pt in FINITE:
            neg = ec17.point_neg(pt)
            # 期望值由独立参考给出。
            self.assertEqual(neg, aff_neg(pt))
            self.assertEqual(neg, exp_neg(pt))
            self.assertIsNone(ec17.point_add(pt, neg))
            self.assertEqual(neg[0], pt[0])
        self.assertIsNone(ec17.point_neg(ec17.INFINITY))

    def test_associativity_full_table(self):
        for p in ALL_POINTS:
            for q in ALL_POINTS:
                pq = ec17.point_add(p, q)
                for r in ALL_POINTS:
                    lhs = ec17.point_add(pq, r)
                    # 右侧用独立指数路线，避免与核心同方法自证。
                    rhs = exp_add(p, exp_add(q, r))
                    self.assertEqual(lhs, rhs, (p, q, r))


class ScalarMulTests(unittest.TestCase):
    def test_scalar_mul_matches_repeated_addition_and_log_table(self):
        for pt in ALL_POINTS:
            for k in range(ORDER):
                core = ec17.scalar_mul(k, pt)
                self.assertEqual(core, aff_mul(k, pt), (k, pt))
                self.assertEqual(core, exp_mul(k, pt), (k, pt))

    def test_zero_scalar_is_infinity(self):
        for pt in ALL_POINTS:
            self.assertIsNone(ec17.scalar_mul(0, pt))

    def test_g_multiples_match_enumeration(self):
        for k in range(ORDER):
            self.assertEqual(ec17.scalar_mul(k, ec17.GENERATOR), MULTIPLES[k])

    def test_distributive_over_scalars(self):
        # (a+b)G = aG + bG，加法侧用独立指数表比对。
        for a in range(ORDER):
            for b in range(ORDER):
                lhs = ec17.scalar_mul((a + b) % ORDER, ec17.GENERATOR)
                rhs = exp_add(MULTIPLES[a], MULTIPLES[b])
                self.assertEqual(lhs, rhs, (a, b))


if __name__ == "__main__":
    unittest.main()
