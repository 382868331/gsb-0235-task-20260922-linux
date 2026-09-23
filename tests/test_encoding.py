"""压缩/标量编码的严格性测试。

期望值（编码字节、恢复点）全部来自独立参考 reference.py；
往返一致只作为补充断言，不充当期望值来源。
"""

import unittest

import ec17
from reference import (
    P_MOD,
    ORDER,
    O,
    finite_points,
    aff_neg,
    ref_encode_point,
    ref_sqrt_candidates,
)

FINITE = finite_points()


class PointEncodingTests(unittest.TestCase):
    def test_encode_all_points_matches_reference_bytes(self):
        # 无穷远与全部 18 个有限点，字节与独立参考逐字节相等。
        self.assertEqual(ec17.encode_point(ec17.INFINITY), b"\x00")
        for pt in FINITE:
            self.assertEqual(
                ec17.encode_point(pt),
                ref_encode_point(pt),
                pt,
            )

    def test_roundtrip_is_supplement_only(self):
        # 补充性质：解码(编码(P)) == P；不是期望值的唯一来源。
        for pt in FINITE:
            self.assertEqual(ec17.decode_point(ec17.encode_point(pt)), pt)
        self.assertIsNone(ec17.decode_point(b"\x00"))

    def test_decode_recovers_reference_point(self):
        # 独立枚举每个前缀与 x，能解码当且仅当参考平方根存在，
        # 且恢复的 y 与参考穷举结果一致。
        for prefix in (0x02, 0x03):
            for x in range(P_MOD):
                roots = ref_sqrt_candidates(x)
                data = bytes((prefix, x))
                if not roots:
                    with self.assertRaises(ec17.PointNotOnCurveError):
                        ec17.decode_point(data)
                    continue
                want_even = prefix == 0x02
                (matching,) = [y for y in roots if (y % 2 == 0) == want_even]
                self.assertEqual(ec17.decode_point(data), (x, matching))

    def test_wrong_parity_prefix_decodes_to_negation_then_signature_rejects(self):
        # 奇偶前缀翻转不是编码错误：它规范地解码为原点点的逆点（独立参考给出）。
        sample = (16, 4)
        good = ec17.encode_point(sample)
        flipped = bytes((good[0] ^ 1, good[1]))
        decoded = ec17.decode_point(flipped)
        self.assertEqual(decoded, aff_neg(sample))
        self.assertNotEqual(decoded, sample)
        # 在真实签名里它导致等式失败（见 test_schnorr 中的端到端用例）。


class RejectMalformedPointEncoding(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(ec17.EmptyEncodingError):
            ec17.decode_point(b"")

    def test_truncated_finite_prefix(self):
        with self.assertRaises(ec17.TruncatedEncodingError):
            ec17.decode_point(b"\x02")
        with self.assertRaises(ec17.TruncatedEncodingError):
            ec17.decode_point(b"\x03")

    def test_invalid_prefix_single_byte(self):
        with self.assertRaises(ec17.InvalidEncodingPrefixError):
            ec17.decode_point(b"\x01")
        with self.assertRaises(ec17.InvalidEncodingPrefixError):
            ec17.decode_point(b"\x04")
        with self.assertRaises(ec17.InvalidEncodingPrefixError):
            ec17.decode_point(b"\xff")

    def test_invalid_prefix_two_bytes(self):
        with self.assertRaises(ec17.InvalidEncodingPrefixError):
            ec17.decode_point(b"\x01\x00")

    def test_x_out_of_domain(self):
        with self.assertRaises(ec17.OutOfDomainEncodingError):
            ec17.decode_point(b"\x02\x11")  # x = 17
        with self.assertRaises(ec17.OutOfDomainEncodingError):
            ec17.decode_point(b"\x03\xff")  # x = 255

    def test_non_shortest_trailing_bytes(self):
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_point(b"\x02\x05\x00")
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_point(b"\x02\x05\x05")

    def test_infinity_with_trailing_bytes_is_non_shortest(self):
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_point(b"\x00\x00")

    def test_allow_infinity_false_rejects_infinity(self):
        with self.assertRaises(ec17.PointAtInfinityError):
            ec17.decode_point(b"\x00", allow_infinity=False)

    def test_bytearray_and_memoryview_accepted_str_rejected(self):
        self.assertEqual(ec17.decode_point(bytearray(b"\x02\x00")), (0, 6))
        self.assertEqual(ec17.decode_point(memoryview(b"\x02\x00")), (0, 6))
        with self.assertRaises(ec17.TypeValidationError):
            ec17.decode_point("0200")


class ScalarEncodingTests(unittest.TestCase):
    def test_all_scalars_match_single_byte(self):
        for n in range(ORDER):
            self.assertEqual(ec17.encode_scalar(n), bytes((n,)))
            self.assertEqual(ec17.decode_scalar(bytes((n,)), name="s"), n)

    def test_scalar_19_is_out_of_domain(self):
        with self.assertRaises(ec17.OutOfDomainEncodingError):
            ec17.decode_scalar(bytes((19,)), name="s")
        with self.assertRaises(ec17.OutOfDomainEncodingError):
            ec17.decode_scalar(b"\xff", name="s")

    def test_scalar_empty_truncated_and_non_shortest(self):
        with self.assertRaises(ec17.EmptyEncodingError):
            ec17.decode_scalar(b"", name="s")
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_scalar(b"\x00\x00", name="s")

    def test_encode_scalar_rejects_bool_and_out_of_range(self):
        with self.assertRaises(ec17.TypeValidationError):
            ec17.encode_scalar(True)
        with self.assertRaises(ec17.ScalarOutOfRangeError):
            ec17.encode_scalar(19)
        with self.assertRaises(ec17.ScalarOutOfRangeError):
            ec17.encode_scalar(-1)


class CoordinateInputTests(unittest.TestCase):
    def test_bool_coordinates_rejected(self):
        with self.assertRaises(ec17.TypeValidationError):
            ec17.point_add((True, 1), ec17.GENERATOR)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.point_add((5, False), ec17.GENERATOR)

    def test_float_coordinates_rejected(self):
        with self.assertRaises(ec17.TypeValidationError):
            ec17.point_add((5.0, 1), ec17.GENERATOR)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.scalar_mul(1.0, ec17.GENERATOR)

    def test_nan_and_infinity_rejected_with_location(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ec17.TypeValidationError) as cm:
                ec17.point_add((bad, 1), ec17.GENERATOR)
            self.assertIn("x", str(cm.exception))

    def test_coordinate_out_of_domain(self):
        with self.assertRaises(ec17.CoordinateOutOfDomainError):
            ec17.point_add((17, 1), ec17.GENERATOR)
        with self.assertRaises(ec17.CoordinateOutOfDomainError):
            ec17.point_add((-1, 1), ec17.GENERATOR)

    def test_in_domain_but_off_curve_rejected(self):
        # (1,1)：x=1 在域内，右端=5 是二次非剩余，点不在曲线上。
        self.assertFalse(ec17.is_on_curve((1, 1)))
        with self.assertRaises(ec17.PointNotOnCurveError):
            ec17.point_add((1, 1), ec17.GENERATOR)

    def test_malformed_point_shape(self):
        with self.assertRaises(ec17.TypeValidationError):
            ec17.point_add([5, 1], ec17.GENERATOR)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.point_add((5, 1, 0), ec17.GENERATOR)


if __name__ == "__main__":
    unittest.main()
