"""两方加法份额协作签名测试。

期望值（聚合公钥、R、e、s）由 tests/reference.py 的独立实现给出；
被测 ec17 不参与期望值计算。反例覆盖：篡改消息、调换会话、一方取消、
重复部分响应、承诺不匹配、无穷远聚合点、nonce 复用。
"""

import unittest

import ec17
from ec17 import (
    Party,
    TwoPartySession,
    aggregate_public_key,
    verify,
    assert_verify,
    challenge,
    scalar_mul,
    point_add,
    GENERATOR,
    GROUP_ORDER,
)
from reference import ORDER, G_POINT, aff_mul, aff_add, ref_challenge, ref_encode_point

SK1, SK2 = 5, 9
K1, K2 = 3, 11
SID = b"session-0001"
MSG = b"two-party teaching demo"


def ref_point(k):
    return aff_mul(k, G_POINT)


def make_parties(sk1=SK1, sk2=SK2):
    return Party(1, sk1), Party(2, sk2)


def run_happy_path(sk1=SK1, sk2=SK2, k1=K1, k2=K2, sid=SID, msg=MSG):
    p1, p2 = make_parties(sk1, sk2)
    session = TwoPartySession(sid, msg, p1, p2)
    c1 = session.commit(1, k1)
    c2 = session.commit(2, k2)
    r1 = session.reveal(1, k1)
    r2 = session.reveal(2, k2)
    s1 = session.partial_response(1)
    s2 = session.partial_response(2)
    sig = session.finalize()
    return p1, p2, session, (c1, c2), (r1, r2), (s1, s2), sig


class HappyPathTests(unittest.TestCase):
    def test_full_protocol_matches_reference(self):
        _, _, session, _, (r1, r2), (s1, s2), sig = run_happy_path()
        exp_p1, exp_p2 = ref_point(SK1), ref_point(SK2)
        exp_pub = aff_add(exp_p1, exp_p2)
        exp_r1, exp_r2 = ref_point(K1), ref_point(K2)
        exp_r = aff_add(exp_r1, exp_r2)
        self.assertEqual(session.aggregate_public_key, exp_pub)
        self.assertEqual((r1, r2), (exp_r1, exp_r2))
        self.assertEqual(sig.r, exp_r)
        e = ref_challenge(exp_r, exp_pub, MSG)
        self.assertEqual(s1, (K1 + e * SK1) % ORDER)
        self.assertEqual(s2, (K2 + e * SK2) % ORDER)
        self.assertEqual(sig.s, (s1 + s2) % ORDER)
        self.assertEqual(sig.message, MSG)

    def test_final_signature_passes_original_verifier(self):
        _, _, session, _, _, _, sig = run_happy_path()
        self.assertTrue(verify(MSG, session.aggregate_public_key, sig.r, sig.s))
        assert_verify(MSG, session.aggregate_public_key, sig.r, sig.s)

    def test_partial_response_equations_hold(self):
        _, _, session, _, (r1, r2), (s1, s2), _ = run_happy_path()
        e = challenge(session.aggregate_nonce, session.aggregate_public_key, MSG)
        for s_i, r_i, sk in ((s1, r1, SK1), (s2, r2, SK2)):
            lhs = scalar_mul(s_i, GENERATOR)
            rhs = point_add(r_i, scalar_mul(e, scalar_mul(sk, GENERATOR)))
            self.assertEqual(lhs, rhs)

    def test_aggregate_public_key_helper(self):
        p1, p2 = make_parties()
        self.assertEqual(
            aggregate_public_key(p1.public_share, p2.public_share),
            aff_add(ref_point(SK1), ref_point(SK2)),
        )

    def test_commitment_binds_session_party_message(self):
        p1, p2 = make_parties()
        base = TwoPartySession(SID, MSG, p1, p2)
        c_base = base.commit(1, K1)
        # 换会话 ID / 换消息 / 换参与方编号，承诺都必须不同。
        p1b, p2b = make_parties()
        other_sid = TwoPartySession(b"session-0002", MSG, p1b, p2b)
        self.assertNotEqual(c_base, other_sid.commit(1, K1))
        p1c, p2c = make_parties()
        other_msg = TwoPartySession(SID, MSG + b"!", p1c, p2c)
        self.assertNotEqual(c_base, other_msg.commit(1, K1))
        p1d, p2d = make_parties()
        swapped = TwoPartySession(SID, MSG, p1d, p2d)
        self.assertNotEqual(c_base, swapped.commit(2, K1))


class NegativeTests(unittest.TestCase):
    def test_tampered_message_fails_original_verifier(self):
        _, _, session, _, _, _, sig = run_happy_path()
        tampered = MSG[:-1] + b"X"
        self.assertFalse(verify(tampered, session.aggregate_public_key, sig.r, sig.s))
        with self.assertRaises(ec17.SignatureMismatchError):
            assert_verify(tampered, session.aggregate_public_key, sig.r, sig.s)

    def test_swapped_session_commitment_mismatch(self):
        # 在会话 A 承诺，却拿到会话 B（不同 session_id）去公开：承诺不匹配。
        p1, p2 = make_parties()
        session_a = TwoPartySession(b"session-A", MSG, p1, p2)
        session_a.commit(1, K1)
        q1, q2 = make_parties()
        session_b = TwoPartySession(b"session-B", MSG, q1, q2)
        session_b.commit(1, K1)
        # 用 A 的 nonce 在 B 公开本身合法（不同会话），真正的调换攻击是：
        # 攻击者把 A 会话的承诺搬到 B 会话的上下文中公开不同 nonce。
        with self.assertRaises(ec17.CommitmentMismatchError):
            session_a.reveal(1, K1 + 1)
        with self.assertRaises(ec17.CommitmentMismatchError):
            session_b.reveal(1, K1 + 2)

    def test_cross_session_partials_do_not_verify(self):
        # 调换会话：把两个不同会话的部分响应手工拼接，原验签器必须拒绝。
        _, _, session_a, _, _, (s1a, _), sig_a = run_happy_path(sid=b"session-X")
        _, _, session_b, _, _, (_, s2b), _ = run_happy_path(sid=b"session-Y", k2=12)
        forged_s = (s1a + s2b) % GROUP_ORDER
        self.assertFalse(
            verify(MSG, session_a.aggregate_public_key, sig_a.r, forged_s)
        )

    def test_commitment_mismatch_on_wrong_nonce(self):
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        session.commit(1, K1)
        with self.assertRaises(ec17.CommitmentMismatchError):
            session.reveal(1, K1 + 1)

    def test_duplicate_partial_response_rejected(self):
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        session.commit(1, K1)
        session.commit(2, K2)
        session.reveal(1, K1)
        session.reveal(2, K2)
        session.partial_response(1)
        with self.assertRaises(ec17.DuplicatePartialResponseError):
            session.partial_response(1)

    def test_infinity_aggregate_nonce_rejected(self):
        # k1 + k2 ≡ 0 (mod 19) → R1 + R2 = O，协议必须中止。
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        session.commit(1, 3)
        session.commit(2, 16)
        session.reveal(1, 3)
        with self.assertRaises(ec17.AggregatePointAtInfinityError):
            session.reveal(2, 16)

    def test_infinity_aggregate_public_key_rejected(self):
        # sk1 + sk2 ≡ 0 (mod 19) → 聚合公钥为 O，会话无法建立。
        p1, p2 = make_parties(4, 15)
        with self.assertRaises(ec17.AggregatePointAtInfinityError):
            TwoPartySession(SID, MSG, p1, p2)
        with self.assertRaises(ec17.AggregatePointAtInfinityError):
            aggregate_public_key(scalar_mul(4, GENERATOR), scalar_mul(15, GENERATOR))

    def test_nonce_reuse_after_reveal_rejected(self):
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        session.commit(1, K1)
        session.reveal(1, K1)
        # 同一方在任何新会话中复用已公开 nonce 都被拒绝。
        session2 = TwoPartySession(b"session-0002", MSG, p1, p2)
        with self.assertRaises(ec17.NonceReuseError):
            session2.commit(1, K1)

    def test_nonce_stays_burned_when_peer_cancels(self):
        # 一方公开 nonce 后另一方退出：已公开 nonce 仍被烧毁。
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        session.commit(1, K1)
        session.commit(2, K2)
        session.reveal(1, K1)
        session.cancel(2)
        with self.assertRaises(ec17.SessionStateError):
            session.reveal(2, K2)
        # 取消后未公开的 K2 被释放，已公开的 K1 永久烧毁。
        session2 = TwoPartySession(b"session-0003", MSG, p1, p2)
        with self.assertRaises(ec17.NonceReuseError):
            session2.commit(1, K1)
        session2.commit(2, K2)  # 未公开过的 nonce 可以再用

    def test_cancel_blocks_all_steps(self):
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        session.cancel(1)
        for op in (
            lambda: session.commit(1, K1),
            lambda: session.reveal(1, K1),
            lambda: session.partial_response(1),
            lambda: session.finalize(),
        ):
            with self.assertRaises(ec17.SessionStateError):
                op()

    def test_out_of_order_steps_rejected(self):
        p1, p2 = make_parties()
        session = TwoPartySession(SID, MSG, p1, p2)
        with self.assertRaises(ec17.SessionStateError):
            session.reveal(1, K1)  # 未承诺就公开
        with self.assertRaises(ec17.SessionStateError):
            session.partial_response(1)  # 未公开就响应
        with self.assertRaises(ec17.SessionStateError):
            session.finalize()  # 响应未齐就合成
        session.commit(1, K1)
        with self.assertRaises(ec17.SessionStateError):
            session.commit(1, K1)  # 重复承诺

    def test_session_not_reusable_after_finalize(self):
        _, _, session, _, _, _, _ = run_happy_path()
        with self.assertRaises(ec17.SessionStateError):
            session.commit(1, 7)

    def test_party_and_session_validation(self):
        with self.assertRaises(ec17.UnknownPartyError):
            Party(3, 5)
        with self.assertRaises(ec17.InvalidSecretKeyError):
            Party(1, 0)
        p1, p2 = make_parties()
        with self.assertRaises(ec17.UnknownPartyError):
            TwoPartySession(SID, MSG, p2, p1)  # 顺序固定 1 先 2 后
        with self.assertRaises(ec17.SessionStateError):
            TwoPartySession(b"", MSG, p1, p2)  # 空会话 ID
        with self.assertRaises(ec17.TypeValidationError):
            TwoPartySession("sid", MSG, p1, p2)  # str 不隐式编码
        with self.assertRaises(ec17.MessageTypeError):
            TwoPartySession(SID, "msg", p1, p2)
        session = TwoPartySession(SID, MSG, p1, p2)
        with self.assertRaises(ec17.UnknownPartyError):
            session.commit(7, K1)


class EncodedInteropTests(unittest.TestCase):
    def test_final_signature_roundtrips_through_original_encoding(self):
        _, _, session, _, _, _, sig = run_happy_path()
        frame = ec17.encode_signature(sig)
        decoded = ec17.decode_signature(frame, MSG)
        self.assertEqual(decoded, sig)
        pub_enc = ec17.encode_point(session.aggregate_public_key)
        self.assertTrue(
            ec17.verify_encoded(MSG, pub_enc, ec17.encode_point(sig.r), bytes([sig.s]))
        )


if __name__ == "__main__":
    unittest.main()
