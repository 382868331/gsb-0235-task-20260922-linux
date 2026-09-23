"""Schnorr 教学签名严格验签测试。

所有期望值（公钥、R、e、s、等式是否成立）由 tests/reference.py 的独立
实现给出；被测 ec17 不参与任何期望值的计算。固定输入如下：
  - 全量组合：secret_key ∈ 1..18、nonce ∈ 1..18（324 对）× 固定消息集；
  - 锚点向量：sk=7, nonce=13, message=b"ec17-schnorr-teaching"。
"""

import hashlib
import unittest

import ec17
from reference import (
    ORDER,
    G_POINT,
    aff_mul,
    aff_add,
    ref_sign,
    ref_verify,
    ref_challenge,
    ref_encode_point,
    finite_points,
)

MESSAGES = [b"", b"ec17-schnorr-teaching", b"hello", b"\x00\x01\x02", b"x"]
ANCHOR_MSG = b"ec17-schnorr-teaching"
FINITE = finite_points()


class SignatureVectorTests(unittest.TestCase):
    def test_anchor_vector(self):
        # 独立参考先算出期望四元组。
        pub, r_point, e_val, s_val = ref_sign(7, ANCHOR_MSG, 13)
        sig = ec17.sign(7, ANCHOR_MSG, 13)
        self.assertEqual(ec17.derive_public_key(7), pub)
        self.assertEqual(sig.r, r_point)
        self.assertEqual(sig.s, s_val)
        self.assertEqual(ec17.challenge(sig.r, pub, ANCHOR_MSG), e_val)
        self.assertTrue(ec17.verify(ANCHOR_MSG, pub, sig.r, sig.s))
        # 与离线核算的固定常数互相印证（独立参考是期望来源，这里只做锚定）。
        self.assertEqual((pub, r_point, e_val, s_val), ((0, 6), (16, 4), 14, 16))

    def test_all_324_sk_nonce_pairs_against_reference(self):
        for sk in range(1, ORDER):
            for nonce in range(1, ORDER):
                for msg in MESSAGES:
                    pub, r_point, e_val, s_val = ref_sign(sk, msg, nonce)
                    sig = ec17.sign(sk, msg, nonce)
                    self.assertEqual(sig.r, r_point, (sk, nonce, msg))
                    self.assertEqual(sig.s, s_val, (sk, nonce, msg))
                    self.assertEqual(ec17.challenge(r_point, pub, msg), e_val)
                    self.assertTrue(ec17.verify(msg, pub, sig.r, sig.s))
                    self.assertTrue(ref_verify(msg, pub, sig.r, sig.s))

    def test_s_equal_zero_is_structure_valid_and_accepted(self):
        # 独立参考可找到 s=0 的合法签名（sk=3, nonce=5, b"hello"）。
        pub, r_point, _e, s_val = ref_sign(3, b"hello", 5)
        self.assertEqual(s_val, 0)
        self.assertTrue(ec17.verify(b"hello", pub, r_point, 0))

    def test_challenge_matches_reference_for_all_point_pairs(self):
        points = FINITE  # R/P 在协议中必须有限
        for r_point in points:
            for pub in points:
                self.assertEqual(
                    ec17.challenge(r_point, pub, ANCHOR_MSG),
                    ref_challenge(r_point, pub, ANCHOR_MSG),
                )


class TamperAndMalleabilityTests(unittest.TestCase):
    def setUp(self):
        self.sk = 7
        self.nonce = 13
        self.msg = ANCHOR_MSG
        self.pub, self.r_point, self.e, self.s = ref_sign(self.sk, self.msg, self.nonce)

    def test_tampered_message_rejected(self):
        tampered = b"ec17-schnorr-teachinh"  # 末字符 g->h
        self.assertFalse(ec17.verify(tampered, self.pub, self.r_point, self.s))
        with self.assertRaises(ec17.SignatureMismatchError):
            ec17.assert_verify(tampered, self.pub, self.r_point, self.s)

    def test_wrong_public_key_rejected(self):
        other_pub = ec17.derive_public_key(self.sk + 1)
        self.assertFalse(ec17.verify(self.msg, other_pub, self.r_point, self.s))

    def test_negated_r_wrong_parity_rejected(self):
        # 翻转压缩奇偶前缀 -> 解码为 -R（独立参考 aff 系列给出）。
        enc_r = ref_encode_point(self.r_point)
        flipped = bytes((enc_r[0] ^ 1, enc_r[1]))
        neg_r = ec17.decode_point(flipped)
        expected = (self.r_point[0], (-self.r_point[1]) % 17)
        self.assertEqual(neg_r, expected)
        # 以重算后的质询验签仍失败。
        self.assertFalse(ec17.verify(self.msg, self.pub, neg_r, self.s))
        # 编码入口同样拒绝。
        self.assertFalse(
            ec17.verify_encoded(
                self.msg, ref_encode_point(self.pub), flipped, bytes((self.s,))
            )
        )

    def test_s_plus_19_malleability_blocked_at_boundary(self):
        # 数学事实（由独立参考证明）：(s+19)·G == s·G，模阶可塑性客观存在。
        self.assertEqual(
            aff_mul(self.s + ORDER, G_POINT), aff_mul(self.s, G_POINT)
        )
        # 但本协议的验签接口在输入边界直接拒绝 s=19，不做隐式模 19 约化。
        with self.assertRaises(ec17.ScalarOutOfRangeError):
            ec17.verify(self.msg, self.pub, self.r_point, self.s + ORDER)
        # 标量编码 0x13 (=19) 属于域外编码。
        with self.assertRaises(ec17.OutOfDomainEncodingError):
            ec17.verify_encoded(
                self.msg,
                ref_encode_point(self.pub),
                ref_encode_point(self.r_point),
                b"\x13",
            )

    def test_s_negative_or_bool_rejected(self):
        for bad in (-1, 18 + 1, 100):
            with self.assertRaises(ec17.ScalarOutOfRangeError):
                ec17.verify(self.msg, self.pub, self.r_point, bad)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.verify(self.msg, self.pub, self.r_point, True)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.verify(self.msg, self.pub, self.r_point, 16.0)

    def test_tampered_s_rejected(self):
        self.assertFalse(ec17.verify(self.msg, self.pub, self.r_point, (self.s + 1) % ORDER))


class InfinityAndOffCurveTests(unittest.TestCase):
    def setUp(self):
        self.pub, self.r_point, _e, self.s = ref_sign(7, ANCHOR_MSG, 13)

    def test_r_infinity_rejected(self):
        with self.assertRaises(ec17.PointAtInfinityError):
            ec17.verify(ANCHOR_MSG, self.pub, ec17.INFINITY, self.s)

    def test_public_key_infinity_rejected(self):
        with self.assertRaises(ec17.PointAtInfinityError):
            ec17.verify(ANCHOR_MSG, ec17.INFINITY, self.r_point, self.s)

    def test_encoded_infinity_r_and_pub_rejected(self):
        with self.assertRaises(ec17.PointAtInfinityError):
            ec17.verify_encoded(
                ANCHOR_MSG, ref_encode_point(self.pub), b"\x00", bytes((self.s,))
            )
        with self.assertRaises(ec17.PointAtInfinityError):
            ec17.verify_encoded(
                ANCHOR_MSG, b"\x00", ref_encode_point(self.r_point), bytes((self.s,))
            )

    def test_off_curve_points_rejected_in_domain(self):
        # (1,1) 在域内但不在曲线上（右端 5 为二次非剩余）。
        with self.assertRaises(ec17.PointNotOnCurveError):
            ec17.verify(ANCHOR_MSG, (1, 1), self.r_point, self.s)
        with self.assertRaises(ec17.PointNotOnCurveError):
            ec17.verify(ANCHOR_MSG, self.pub, (1, 1), self.s)

    def test_out_of_domain_points_rejected(self):
        with self.assertRaises(ec17.CoordinateOutOfDomainError):
            ec17.verify(ANCHOR_MSG, self.pub, (17, 4), self.s)


class SigningInputTests(unittest.TestCase):
    def test_secret_key_must_be_1_to_18(self):
        for bad in (0, 19, -1):
            with self.assertRaises(ec17.InvalidSecretKeyError):
                ec17.sign(bad, b"m", 1)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.sign(True, b"m", 1)

    def test_nonce_zero_and_out_of_range_rejected(self):
        with self.assertRaises(ec17.InvalidNonceError):
            ec17.sign(1, b"m", 0)
        for bad in (19, -1):
            with self.assertRaises(ec17.InvalidNonceError):
                ec17.sign(1, b"m", bad)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.sign(1, b"m", False)

    def test_message_must_be_bytes(self):
        with self.assertRaises(ec17.MessageTypeError):
            ec17.sign(1, "not-bytes", 1)
        with self.assertRaises(ec17.MessageTypeError):
            ec17.verify("not-bytes", ec17.derive_public_key(1), FINITE[0], 1)

    def test_message_length_limit(self):
        big = b"a" * (ec17.MAX_MESSAGE_BYTES + 1)
        with self.assertRaises(ec17.MessageTooLongError):
            ec17.sign(1, big, 1)
        # 恰好等于上限的消息允许。
        ok = b"a" * ec17.MAX_MESSAGE_BYTES
        sig = ec17.sign(1, ok, 1)
        self.assertTrue(ec17.verify(ok, ec17.derive_public_key(1), sig.r, sig.s))


class SignatureEncodingTests(unittest.TestCase):
    def test_fixed_three_byte_encoding(self):
        pub, r_point, _e, s_val = ref_sign(7, ANCHOR_MSG, 13)
        sig = ec17.sign(7, ANCHOR_MSG, 13)
        encoded = ec17.encode_signature(sig)
        self.assertEqual(encoded, ref_encode_point(r_point) + bytes((s_val,)))
        self.assertEqual(encoded, bytes.fromhex("021010"))
        decoded = ec17.decode_signature(encoded, ANCHOR_MSG)
        self.assertEqual((decoded.r, decoded.s), (r_point, s_val))
        self.assertTrue(
            ec17.verify(ANCHOR_MSG, pub, decoded.r, decoded.s)
        )

    def test_signature_encoding_length_enforced(self):
        with self.assertRaises(ec17.EmptyEncodingError):
            ec17.decode_signature(b"", ANCHOR_MSG)
        with self.assertRaises(ec17.TruncatedEncodingError):
            ec17.decode_signature(b"\x02\x10", ANCHOR_MSG)
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_signature(b"\x02\x10\x10\x00", ANCHOR_MSG)

    def test_signature_encoding_rejects_infinity_r(self):
        # 在固定 3 字节帧中，R 槽恰为 2 字节；0x00 后再带字节属于非最短
        # 编码（无穷远的唯一编码是单字节 0x00，无法放进 2 字节槽），
        # 因此在 allow_infinity 检查之前即以 NonShortestEncodingError 拒绝。
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_signature(b"\x00\x10\x10", ANCHOR_MSG)
        # 单独解码 2 字节 0x00 槽时同样不放行无穷远。
        with self.assertRaises(ec17.NonShortestEncodingError):
            ec17.decode_point(b"\x00\x10", allow_infinity=False)

    def test_signature_encoding_rejects_s_19(self):
        with self.assertRaises(ec17.OutOfDomainEncodingError):
            ec17.decode_signature(b"\x02\x10\x13", ANCHOR_MSG)

    def test_signature_encoding_rejects_off_curve_r(self):
        # x=1 无曲线点（二次非剩余）。
        with self.assertRaises(ec17.PointNotOnCurveError):
            ec17.decode_signature(b"\x02\x01\x10", ANCHOR_MSG)


if __name__ == "__main__":
    unittest.main()
