"""两方加法份额协作签名演示（真实计算，无网络、无随机源、无 sleep）。

运行：python demo_iteration.py

演示内容：
  1. 两方各持加法私钥份额，聚合公钥 = 份额公钥之和；
  2. 完整四轮协议（承诺 → 公开 → 部分响应 → 合成），合成签名交**原验签器**；
  3. 边界情况：一方公开 nonce 后另一方退出，该 nonce 份额永久不可复用。

警告：全部数据为写死的合成教学数据，严禁用于真实场景。
"""

import time

import ec17


def main():
    started = time.perf_counter()

    print("== ec17 两方加法份额协作签名演示 ==")

    # --- 合成固定教学数据 -------------------------------------------------
    sk1, sk2 = 5, 8                 # 加法私钥份额（合成，禁止真实密钥）
    k1, k2 = 3, 11                  # nonce 份额（显式给定）
    session_id = b"session-0001"
    message = b"two-party-demo"

    party1 = ec17.Party(1, sk1)
    party2 = ec17.Party(2, sk2)
    p_agg = ec17.point_add(party1.public_share, party2.public_share)
    print(f"份额公钥 P1={party1.public_share}  P2={party2.public_share}")
    print(f"聚合公钥 P = P1 + P2 = {p_agg}（编码 {ec17.encode_point(p_agg).hex()}）")

    # --- 正常路径：完整四轮 ----------------------------------------------
    print("\n-- 正常路径：四轮协作签名 --")
    sess1 = party1.start_session(session_id, message, party2, k1)
    sess2 = party2.start_session(session_id, message, party1, k2)

    sess1.receive_commitment(sess2.commitment)
    sess2.receive_commitment(sess1.commitment)
    print(f"1. 交换承诺   c1={sess1.commitment.hex()[:16]}… c2={sess2.commitment.hex()[:16]}…")

    rev1, rev2 = sess1.reveal(), sess2.reveal()
    sess1.receive_reveal(rev2)
    sess2.receive_reveal(rev1)
    r_agg = sess1._r_agg
    print(f"2. 公开 nonce 点 R1={rev1.hex()} R2={rev2.hex()}，聚合 R={r_agg}")

    s1, s2 = sess1.partial_response(), sess2.partial_response()
    sess1.receive_partial(s2)
    sess2.receive_partial(s1)
    print(f"3. 部分响应   s1={s1} s2={s2}（双方已逐项验证 s_i·G == R_i + e·P_i）")

    signature = sess1.finalize()
    ok = ec17.verify(signature.message, p_agg, signature.r, signature.s)
    print(f"4. 合成签名   R={signature.r} s={signature.s}")
    print(f"   绑定消息 bound = {signature.message!r}")
    print(f"   原验签器 verify(bound, P, R, s) = {ok}")

    # --- 边界情况：一方退出后 nonce 份额不可复用 --------------------------
    print("\n-- 边界情况：一方退出，已公开 nonce 份额不可复用 --")
    quitter = ec17.Party(1, sk1)
    peer = ec17.Party(2, sk2)
    abandoned = quitter.start_session(b"session-0002", message, peer, 7)
    abandoned.reveal()  # quitter 已公开 nonce=7；peer 随后退出，会话中止。
    print(f"会话中止后已烧掉的 nonce：{sorted(quitter.burned_nonces)}")
    retry = quitter.start_session(b"session-0003", message, peer, 7)
    try:
        retry.reveal()
    except ec17.NonceReuseError as exc:
        print(f"如预期拒绝复用（{type(exc).__name__}）：{exc}")

    elapsed = time.perf_counter() - started
    print(f"\n演示完成，实际计算耗时 {elapsed:.3f} 秒（无 sleep、无预录结果）。")


if __name__ == "__main__":
    main()
