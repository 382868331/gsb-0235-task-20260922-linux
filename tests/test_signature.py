"""Schnorr 风格教学签名/严格验签测试。

覆盖：全部 d,k ∈ 1..18 的合成签名与独立参考 ref_verify 交叉；
手写硬编码挑战向量（锁定 SHA256 原语拼接与字节序）；
s 越界（含 s+19 可塑性）；错误奇偶；无穷远 R/P；非最短/域外编码；
消息/公钥/R/s 篡改导致的方程失败；Signature 结构契约。
"""

from __future__ import annotations

import hashlib
import unittest

from ecc_teach import core
from ecc_teach.errors import (
    InvalidSignatureError,
    NonFiniteNumberError,
    StrictTypeError,
)

import reference as ref

MSG = b"teaching-schnorr"
D_FIXED, K_FIXED = 7, 11


def _reason(ctx) -> str:
    return ctx.exception.reason


class TestHardcodedVector(unittest.TestCase):
    """所有数字手写/独立计算，禁止从被测实现反取。"""

    def test_challenge_preimage_and_digest(self) -> None:
        # 独立公式：11G=(13,10), 7G=(0,6)
        self.assertEqual(ref.ref_mul(K_FIXED, (5, 1)), (13, 10))
        self.assertEqual(ref.ref_mul(D_FIXED, (5, 1)), (0, 6))
        r_point = (13, 10)
        pub_point = (0, 6)

        preimage = b"\x02\r" + b"\x02\x00" + MSG  # R编 ‖ P编 ‖ message
        digest = hashlib.sha256(preimage).digest()
        self.assertEqual(
            digest.hex(), "7411e71725fba822d90392b3e2e541e5943a429fb15ed094ba846e93f8acba5b"
        )
        e = int.from_bytes(digest, "big") % 19
        self.assertEqual(e, 15)
        self.assertEqual(core.challenge(r_point, pub_point, MSG), 15)

    def test_hardcoded_signature_verifies(self) -> None:
        # s = k + e*d = 11 + 15*7 = 116 ≡ 2 (mod 19)
        sig = core.Signature(2, b"\x02\r")
        self.assertIs(sig, sig)  # tuple 结构可重复使用、无状态
        self.assertTrue(core.verify_signature(b"\x02\x00", MSG, sig))
        self.assertEqual(core.sign_scalar(D_FIXED, MSG, K_FIXED), sig)
        # 独立参考独立验签同样成立。
        self.assertTrue(ref.ref_verify(b"\x02\x00", MSG, 2, b"\x02\r"))


class TestAllSyntheticSignatures(unittest.TestCase):
    """穷举 d∈1..18、k∈1..18、多条固定消息：核心验签 <-> 独立参考验签。"""

    MESSAGES = [b"", b"a", b"\x00\x01\x02", "中文消息".encode(), b"x" * 1000]

    def test_full_grid_against_reference(self) -> None:
        for d in range(1, 19):
            pub_enc = core.derive_public_key(d)
            pub_ref = ref.ref_mul(d, (5, 1))
            self.assertEqual(pub_enc, ref.ref_encode(pub_ref))
            for k in range(1, 19):
                for m in self.MESSAGES:
                    with self.subTest(d=d, k=k, m=m[:8]):
                        sig = core.sign_scalar(d, m, k)
                        # 独立参考独立合成出的 (s, Renc) 必须完全相等。
                        s_ref, r_ref = ref.ref_sign(d, m, k)
                        self.assertEqual(sig.s, s_ref)
                        self.assertEqual(sig.r_encoding, r_ref)
                        # 两边互相验签。
                        self.assertTrue(core.verify_signature(pub_enc, m, sig))
                        self.assertTrue(ref.ref_verify(pub_enc, m, sig.s, sig.r_encoding))

    def test_nonce_must_be_explicit_and_valid(self) -> None:
        with self.assertRaises(TypeError):
            core.sign_scalar(3, b"m")  # type: ignore[call-arg]
        with self.assertRaises(ValueError):
            core.sign_scalar(3, b"m", 0)    # k=0 -> R=O
        with self.assertRaises(ValueError):
            core.sign_scalar(3, b"m", 19)
        with self.assertRaises(StrictTypeError):
            core.sign_scalar(3, b"m", True)


class TestSVerification(unittest.TestCase):
    def setUp(self) -> None:
        self.pub = core.derive_public_key(D_FIXED)
        self.sig = core.sign_scalar(D_FIXED, MSG, K_FIXED)

    def test_s_plus_19_malleability_rejected(self) -> None:
        for delta in (19, 38, -19):
            with self.subTest(delta=delta):
                forged = core.Signature(self.sig.s + delta, self.sig.r_encoding)
                with self.assertRaises(InvalidSignatureError) as ctx:
                    core.verify_signature(self.pub, MSG, forged)
                self.assertEqual(_reason(ctx), "s_range")
                self.assertFalse(core.is_signature_valid(self.pub, MSG, forged))

    def test_s_boundary_values(self) -> None:
        # s=0 与 s=18 作为输入不越界（是否方程成立另算）。
        sig0 = core.Signature(0, self.sig.r_encoding)
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(self.pub, MSG, sig0)
        self.assertEqual(_reason(ctx), "equation_fail")
        sig18 = core.Signature(18, self.sig.r_encoding)
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(self.pub, MSG, sig18)
        self.assertEqual(_reason(ctx), "equation_fail")
        for bad in (-1, 19, 100):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidSignatureError) as ctx:
                    core.verify_signature(self.pub, MSG, core.Signature(bad, self.sig.r_encoding))
                self.assertEqual(_reason(ctx), "s_range")

    def test_s_type_strict(self) -> None:
        for bad_s in (True, False, 1.0, float("nan"), float("inf"), "2", None):
            with self.subTest(bad_s=bad_s):
                with self.assertRaises((StrictTypeError, NonFiniteNumberError)):
                    core.verify_signature(
                        self.pub, MSG, core.Signature(bad_s, self.sig.r_encoding)  # type: ignore[arg-type]
                    )


class TestPointAndEncodingRejections(unittest.TestCase):
    def setUp(self) -> None:
        self.pub = core.derive_public_key(D_FIXED)
        self.sig = core.sign_scalar(D_FIXED, MSG, K_FIXED)

    def test_flipped_parity_r_decodes_to_negation_then_equation_fails(self) -> None:
        """翻转 R 的奇偶位在本曲线上不是字节非法：它唯一地解码成 -R，
        因此严格验签必须在方程检查处拒绝（equation_fail）。"""
        flipped = bytes([0x03 if self.sig.r_encoding[0] == 0x02 else 0x02,
                         self.sig.r_encoding[1]])
        neg_r = core.point_neg(core.decode_point(self.sig.r_encoding))
        self.assertEqual(core.decode_point(flipped), neg_r)  # 先确认解码语义
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(self.pub, MSG, core.Signature(self.sig.s, flipped))
        self.assertEqual(_reason(ctx), "equation_fail")

    def test_flipped_parity_public_key_decodes_to_negation_then_equation_fails(self) -> None:
        flipped = bytes([0x03 if self.pub[0] == 0x02 else 0x02, self.pub[1]])
        neg_pub = core.point_neg(core.decode_point(self.pub))
        self.assertEqual(core.decode_point(flipped), neg_pub)
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(flipped, MSG, self.sig)
        self.assertEqual(_reason(ctx), "equation_fail")

    def test_infinity_r_and_public(self) -> None:
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(self.pub, MSG, core.Signature(self.sig.s, b"\x00"))
        self.assertEqual(_reason(ctx), "r_infinity")
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(b"\x00", MSG, self.sig)
        self.assertEqual(_reason(ctx), "public_key_infinity")

    def test_nonminimal_and_offdomain_in_verification(self) -> None:
        cases = [
            (self.pub, b"\x02\r\x00", "r_encoding"),       # R 多余后缀
            (self.pub, b"\x02\x11", "r_encoding"),         # R x=17 域外
            (b"\x02\x11", self.sig.r_encoding, "public_key_encoding"),
            (b"\x02\x00\x00", self.sig.r_encoding, "public_key_encoding"),
        ]
        for pub, renc, reason in cases:
            with self.subTest(pub=pub, renc=renc):
                with self.assertRaises(InvalidSignatureError) as ctx:
                    core.verify_signature(pub, MSG, core.Signature(self.sig.s, renc))
                self.assertEqual(_reason(ctx), reason)

    def test_off_curve_coordinate_but_valid_parity_shape(self) -> None:
        # x=1 处曲线上无点：任何前缀都必须按编码非法拒绝。
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(self.pub, MSG, core.Signature(self.sig.s, b"\x02\x01"))
        self.assertEqual(_reason(ctx), "r_encoding")


class TestDecisionConsistencyExhaustive(unittest.TestCase):
    """穷举所有 (s, R编码, 消息, 公钥) 组合，被测接受集合必须与独立参考逐格一致。

    合法签名空间本就极小（s 19 种 × R 18 种 = 342 个候选/消息/公钥），
    因此可以做全空间判定对照，而不只是抽样。
    """

    MESSAGES = [b"", b"consistency", b"\xff\x00", "穷举对照".encode()]
    PUBS = [1, 7, 13, 18]

    def test_boolean_decision_matches_reference_everywhere(self) -> None:
        r_encs = [ref.ref_encode(pt) for pt in ref.all_affine_points()]
        mismatches = 0
        for d in self.PUBS:
            pub_enc = ref.ref_encode(ref.ref_mul(d, (5, 1)))
            for m in self.MESSAGES:
                for s in range(19):
                    for r_enc in r_encs:
                        got = core.is_signature_valid(
                            pub_enc, m, core.Signature(s, r_enc)
                        )
                        want = ref.ref_verify(pub_enc, m, s, r_enc)
                        if got != want:
                            mismatches += 1
        self.assertEqual(mismatches, 0)

    def test_exactly_eighteen_valid_signatures_per_message(self) -> None:
        """固定 (d,m)：342 个 (s,R) 候选中恰好 18 个通过——每个非 O 的 R
        唯一确定 s=k+e·d mod19（k 为 R 的离散对数，1..18）。它们必须正好
        就是 sign_scalar 在 nonce=1..18 下产生的 18 个签名。"""
        r_encs = [ref.ref_encode(pt) for pt in ref.all_affine_points()]
        d, m = 7, b"count-valid"
        pub_enc = core.derive_public_key(d)
        accepted = []
        for s in range(19):
            for r_enc in r_encs:
                if core.is_signature_valid(pub_enc, m, core.Signature(s, r_enc)):
                    accepted.append((s, r_enc))
        self.assertEqual(len(accepted), 18)
        self.assertEqual(len({r for _, r in accepted}), 18)  # 每个 R 恰好一个 s
        produced = {(sig.s, sig.r_encoding) for sig in (
            core.sign_scalar(d, m, k) for k in range(1, 19)
        )}
        self.assertEqual(produced, set(accepted))


class TestEquationFailures(unittest.TestCase):
    def setUp(self) -> None:
        self.pub = core.derive_public_key(D_FIXED)
        self.sig = core.sign_scalar(D_FIXED, MSG, K_FIXED)

    def test_message_tampering(self) -> None:
        for tampered in (b"teaching-schnorX", b"teaching-schnorr\x00", b""):
            if tampered == MSG:
                continue
            with self.subTest(m=tampered):
                with self.assertRaises(InvalidSignatureError) as ctx:
                    core.verify_signature(self.pub, tampered, self.sig)
                self.assertEqual(_reason(ctx), "equation_fail")

    def test_s_tampering_by_one(self) -> None:
        for new_s in ((self.sig.s - 1) % 19, (self.sig.s + 1) % 19):
            with self.subTest(new_s=new_s):
                with self.assertRaises(InvalidSignatureError) as ctx:
                    core.verify_signature(
                        self.pub, MSG, core.Signature(new_s, self.sig.r_encoding)
                    )
                self.assertEqual(_reason(ctx), "equation_fail")

    def test_r_swapped_to_another_valid_point(self) -> None:
        # 换成另一个“合法编码的曲线上点”（3G=(10,6)），编码合法但方程失败。
        other = core.encode_point((10, 6))
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(self.pub, MSG, core.Signature(self.sig.s, other))
        self.assertEqual(_reason(ctx), "equation_fail")

    def test_wrong_public_key(self) -> None:
        other_pub = core.derive_public_key((D_FIXED % 18) + 1)  # 另一个合法公钥
        if other_pub == self.pub:
            other_pub = core.derive_public_key(D_FIXED + 1)
        with self.assertRaises(InvalidSignatureError) as ctx:
            core.verify_signature(other_pub, MSG, self.sig)
        self.assertEqual(_reason(ctx), "equation_fail")


class TestSignatureStructure(unittest.TestCase):
    def setUp(self) -> None:
        self.pub = core.derive_public_key(D_FIXED)
        self.sig = core.sign_scalar(D_FIXED, MSG, K_FIXED)

    def test_plain_tuple_is_not_signature(self) -> None:
        with self.assertRaises(StrictTypeError):
            core.verify_signature(self.pub, MSG, (self.sig.s, self.sig.r_encoding))

    def test_signature_is_tuple_and_immutable(self) -> None:
        self.assertIsInstance(self.sig, tuple)
        self.assertEqual(tuple(self.sig), (2, b"\x02\r"))
        with self.assertRaises(TypeError):
            self.sig[0] = 5  # type: ignore[index]

    def test_nonbytes_fields_are_contract_errors(self) -> None:
        with self.assertRaises(StrictTypeError):
            core.verify_signature(
                self.pub, MSG,
                core.Signature(self.sig.s, "\x02\r"),  # type: ignore[arg-type]
            )
        with self.assertRaises(StrictTypeError):
            core.verify_signature("\x02\x00", MSG, self.sig)  # type: ignore[arg-type]

    def test_verify_returns_true_and_helper_bool(self) -> None:
        self.assertIs(core.verify_signature(self.pub, MSG, self.sig), True)
        self.assertIs(core.is_signature_valid(self.pub, MSG, self.sig), True)
        bad = core.Signature((self.sig.s + 1) % 19, self.sig.r_encoding)
        self.assertIs(core.is_signature_valid(self.pub, MSG, bad), False)

    def test_challenge_rejects_infinity(self) -> None:
        with self.assertRaises(core.InvalidPointError):
            core.challenge(None, (0, 6), MSG)
        with self.assertRaises(core.InvalidPointError):
            core.challenge((13, 10), None, MSG)
        with self.assertRaises(core.InvalidPointError):
            core.challenge((13, 11), (0, 6), MSG)  # (13,11) 不在曲线


if __name__ == "__main__":
    unittest.main()
