"""两方加法份额协作签名现场演示（固定合成数据，无随机源，无 sleep）。

演示内容：
  1. 两方各持加法私钥份额，聚合公钥 P = P1 + P2；
  2. 完整跑一遍 commit → reveal → partial → finalize，
     合成签名交原单方验签器验证；
  3. 边界情况：一方公开 nonce 后另一方退出，已公开 nonce 永久烧毁，
     复用即被 NonceReuseError 拒绝。

运行：python demo_iteration.py（远低于 90 秒，全部现场计算）。
"""

import ec17
from ec17 import Party, TwoPartySession

SK1, SK2 = 5, 9          # 合成教学私钥份额（非真实密钥）
K1, K2 = 3, 11           # 合成 nonce 份额
SID = b"demo-session-001"
MSG = b"ec17 two-party signing demo"


def main():
    print("== 两方加法份额协作签名（ec17 教学曲线，仅教学不安全）==")
    alice, bob = Party(1, SK1), Party(2, SK2)
    session = TwoPartySession(SID, MSG, alice, bob)
    print(f"会话 {SID!r}，消息 {MSG!r}")
    print(f"P1={alice.public_share}  P2={bob.public_share}  聚合公钥 P={session.aggregate_public_key}")

    c1 = session.commit(1, K1)
    c2 = session.commit(2, K2)
    print(f"1) 承诺 c1={c1.hex()[:16]}… c2={c2.hex()[:16]}…")

    r1 = session.reveal(1, K1)
    r2 = session.reveal(2, K2)
    print(f"2) 公开 R1={r1} R2={r2}，聚合 R={session.aggregate_nonce}")

    s1 = session.partial_response(1)
    s2 = session.partial_response(2)
    print(f"3) 部分响应 s1={s1} s2={s2}（各自等式 s_i·G = R_i + e·P_i 已逐项验证）")

    sig = session.finalize()
    ok = ec17.verify(MSG, session.aggregate_public_key, sig.r, sig.s)
    print(f"4) 合成签名 (R={sig.r}, s={sig.s})，原验签器 verify → {ok}")
    assert ok

    print()
    print("== 边界情况：一方公开 nonce 后另一方退出，nonce 永久烧毁 ==")
    carol, dave = Party(1, 7), Party(2, 4)
    aborted = TwoPartySession(b"demo-session-002", MSG, carol, dave)
    aborted.commit(1, 6)
    aborted.commit(2, 8)
    aborted.reveal(1, 6)
    print("carol 已公开 nonce=6，dave 随后 cancel 退出")
    aborted.cancel(2)
    try:
        aborted.reveal(2, 8)
    except ec17.SessionStateError as exc:
        print(f"已取消会话继续操作 → SessionStateError: {exc}")
    retry = TwoPartySession(b"demo-session-003", MSG, carol, dave)
    try:
        retry.commit(1, 6)
    except ec17.NonceReuseError as exc:
        print(f"新会话复用已公开 nonce → NonceReuseError: {exc}")
    print("演示结束：全部现场计算，无预录、无 sleep。")


if __name__ == "__main__":
    main()

