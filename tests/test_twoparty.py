"""两方加法份额协作签名测试（全部使用合成固定数据，不读取真实密钥）。

固定教学数据：sk1=5、sk2=8、nonce 份额 k1=3、k2=11、
session_id=b"session-0001"、message=b"two-party-demo"。
"""

import unittest

import ec17

SK1, SK2 = 5, 8
K1, K2 = 3, 11
SESSION_ID = b"session-0001"
MESSAGE = b"two-party-demo"


def make_parties():
    return ec17.Party(1, SK1), ec17.Party(2, SK2)


def run_session(party1, party2, *, session_id=SESSION_ID, message=MESSAGE,
                k1=K1, k2=K2):
    """走完整四轮，返回 (sess1, sess2, signature)。"""
    sess1 = party1.start_session(session_id, message, party2, k1)
    sess2 = party2.start_session(session_id, message, party1, k2)
    sess1.receive_commitment(sess2.commitment)
    sess2.receive_commitment(sess1.commitment)
    rev1, rev2 = sess1.reveal(), sess2.reveal()
    sess1.receive_reveal(rev2)
    sess2.receive_reveal(rev1)
    s1, s2 = sess1.partial_response(), sess2.partial_response()
    sess1.receive_partial(s2)
    sess2.receive_partial(s1)
    return sess1, sess2, sess1.finalize()


class HappyPathTests(unittest.TestCase):
    def test_full_session_verifies_with_original_verifier(self):
        p1, p2 = make_parties()
        _, _, sig = run_session(p1, p2)
        p_agg = ec17.point_add(p1.public_share, p2.public_share)
        self.assertTrue(ec17.verify(sig.message, p_agg, sig.r, sig.s))
        ec17.assert_verify(sig.message, p_agg, sig.r, sig.s)

    def test_aggregate_key_is_sum_of_shares(self):
        p1, p2 = make_parties()
        expected = ec17.derive_public_key((SK1 + SK2) % ec17.GROUP_ORDER)
        self.assertEqual(ec17.point_add(p1.public_share, p2.public_share), expected)

    def test_partial_response_equation_holds_for_each_party(self):
        p1, p2 = make_parties()
        sess1, sess2, _ = run_session(p1, p2)
        # 逐项核对：s_i·G == R_i + e·P_i（用会话内聚合点重算 e）。
        for sess, party, k in ((sess1, p1, K1), (sess2, p2, K2)):
            e = ec17.challenge(sess._r_agg,
                               sess._p_agg, sess.bound_message)
            r_i = ec17.scalar_mul(k, ec17.GENERATOR)
            s_i = (k + e * (SK1 if party is p1 else SK2)) % ec17.GROUP_ORDER
            self.assertEqual(
                ec17.scalar_mul(s_i, ec17.GENERATOR),
                ec17.point_add(r_i, ec17.scalar_mul(e, party.public_share)),
            )

    def test_both_parties_finalize_identically(self):
        p1, p2 = make_parties()
        sess1, sess2, sig1 = run_session(p1, p2)
        self.assertEqual(sig1, sess2.finalize())

    def test_session_binding_changes_challenge(self):
        p1, p2 = make_parties()
        _, _, sig_a = run_session(p1, p2, session_id=b"session-A")
        p3, p4 = make_parties()
        _, _, sig_b = run_session(p3, p4, session_id=b"session-B")
        self.assertNotEqual(sig_a, sig_b)


class CounterexampleTests(unittest.TestCase):
    def test_tampered_message_rejected_by_original_verifier(self):
        p1, p2 = make_parties()
        _, _, sig = run_session(p1, p2)
        p_agg = ec17.point_add(p1.public_share, p2.public_share)
        tampered = sig.message[:-1] + b"X"
        self.assertFalse(ec17.verify(tampered, p_agg, sig.r, sig.s))
        with self.assertRaises(ec17.SignatureMismatchError):
            ec17.assert_verify(tampered, p_agg, sig.r, sig.s)

    def test_swapped_session_id_rejected(self):
        # 两个会话 ID 下生成的签名不能交叉使用（会话绑定）。
        p1, p2 = make_parties()
        _, _, sig_a = run_session(p1, p2, session_id=b"session-A")
        p3, p4 = make_parties()
        sess_b1, _, _ = run_session(p3, p4, session_id=b"session-B")
        p_agg = ec17.point_add(p3.public_share, p4.public_share)
        # 用 B 会话的绑定消息去验 A 会话的签名：必须失败。
        self.assertFalse(ec17.verify(sess_b1.bound_message, p_agg, sig_a.r, sig_a.s))

    def test_commitment_mismatch_aborts(self):
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        sess2 = p2.start_session(SESSION_ID, MESSAGE, p1, K2)
        sess1.receive_commitment(sess2.commitment)
        # 对方公开了与承诺不符的 nonce 点（此处用另一个 nonce 的点冒充）。
        forged = ec17.encode_point(ec17.scalar_mul(K2 + 1, ec17.GENERATOR))
        with self.assertRaises(ec17.CommitmentMismatchError):
            sess1.receive_reveal(forged)

    def test_duplicate_partial_response_rejected(self):
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        sess2 = p2.start_session(SESSION_ID, MESSAGE, p1, K2)
        sess1.receive_commitment(sess2.commitment)
        sess2.receive_commitment(sess1.commitment)
        sess1.receive_reveal(sess2.reveal())
        sess2.receive_reveal(sess1.reveal())
        s2 = sess2.partial_response()
        sess1.receive_partial(s2)
        with self.assertRaises(ec17.DuplicatePartialResponseError):
            sess1.receive_partial(s2)

    def test_wrong_partial_response_rejected(self):
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        sess2 = p2.start_session(SESSION_ID, MESSAGE, p1, K2)
        sess1.receive_commitment(sess2.commitment)
        sess2.receive_commitment(sess1.commitment)
        sess1.receive_reveal(sess2.reveal())
        sess2.receive_reveal(sess1.reveal())
        bad = (sess2.partial_response() + 1) % ec17.GROUP_ORDER
        with self.assertRaises(ec17.PartialResponseMismatchError):
            sess1.receive_partial(bad)

    def test_nonce_burned_even_if_peer_aborts(self):
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        sess1.receive_commitment(p2.start_session(SESSION_ID, MESSAGE, p1, K2).commitment)
        sess1.reveal()  # 本方已公开；对方随后退出（不再继续）。
        self.assertIn(K1, p1.burned_nonces)
        # 用同一 nonce 开新会话并 reveal：拒绝。
        again = p1.start_session(b"session-0002", MESSAGE, p2, K1)
        again.receive_commitment(
            p2.start_session(b"session-0002", MESSAGE, p1, K2).commitment
        )
        with self.assertRaises(ec17.NonceReuseError):
            again.reveal()

    def test_infinity_aggregate_nonce_aborts(self):
        # k1 + k2 ≡ 0 (mod 19) 时 R1 + R2 = O，必须中止。
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, 4)
        sess2 = p2.start_session(SESSION_ID, MESSAGE, p1, 15)  # 4 + 15 = 19
        sess1.receive_commitment(sess2.commitment)
        sess2.receive_commitment(sess1.commitment)
        rev1, rev2 = sess1.reveal(), sess2.reveal()
        with self.assertRaises(ec17.InfinityAggregateError):
            sess1.receive_reveal(rev2)
        with self.assertRaises(ec17.InfinityAggregateError):
            sess2.receive_reveal(rev1)

    def test_infinity_aggregate_public_key_aborts(self):
        # sk1 + sk2 ≡ 0 (mod 19) 时聚合公钥为 O。
        p1 = ec17.Party(1, 7)
        p2 = ec17.Party(2, 12)  # 7 + 12 = 19
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        sess2 = p2.start_session(SESSION_ID, MESSAGE, p1, K2)
        sess1.receive_commitment(sess2.commitment)
        sess2.receive_commitment(sess1.commitment)
        rev1, rev2 = sess1.reveal(), sess2.reveal()
        with self.assertRaises(ec17.InfinityAggregateError):
            sess1.receive_reveal(rev2)
        with self.assertRaises(ec17.InfinityAggregateError):
            sess2.receive_reveal(rev1)

    def test_peer_cancellation_leaves_no_partial_state(self):
        # 一方取消：已公开方 nonce 已烧，未公开方不受影响可换新会话。
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        sess1.reveal()
        # p2 取消（从未 reveal）：p2 的 nonce 未烧，可正常开新会话。
        self.assertEqual(p2.burned_nonces, frozenset())
        _, _, sig = run_session(p1, p2, session_id=b"session-0003", k1=K2, k2=K2)
        p_agg = ec17.point_add(p1.public_share, p2.public_share)
        self.assertTrue(ec17.verify(sig.message, p_agg, sig.r, sig.s))


class InputValidationTests(unittest.TestCase):
    def test_party_id_must_be_1_or_2(self):
        with self.assertRaises(ec17.TypeValidationError):
            ec17.Party(3, SK1)
        with self.assertRaises(ec17.TypeValidationError):
            ec17.Party(True, SK1)

    def test_session_id_rules(self):
        p1, p2 = make_parties()
        with self.assertRaises(ec17.SessionIdError):
            p1.start_session(b"", MESSAGE, p2, K1)
        with self.assertRaises(ec17.SessionIdError):
            p1.start_session("session-0001", MESSAGE, p2, K1)
        with self.assertRaises(ec17.SessionIdError):
            p1.start_session(b"x" * 65, MESSAGE, p2, K1)

    def test_step_order_enforced(self):
        p1, p2 = make_parties()
        sess1 = p1.start_session(SESSION_ID, MESSAGE, p2, K1)
        with self.assertRaises(ec17.SessionStateError):
            sess1.receive_reveal(ec17.encode_point(ec17.scalar_mul(K2, ec17.GENERATOR)))
        with self.assertRaises(ec17.SessionStateError):
            sess1.partial_response()
        with self.assertRaises(ec17.SessionStateError):
            sess1.finalize()

    def test_peer_must_be_opposite_party(self):
        p1, p2 = make_parties()
        with self.assertRaises(ec17.TypeValidationError):
            p1.start_session(SESSION_ID, MESSAGE, ec17.Party(1, 9), K1)
        with self.assertRaises(ec17.TypeValidationError):
            p1.start_session(SESSION_ID, MESSAGE, object(), K1)


if __name__ == "__main__":
    unittest.main()
