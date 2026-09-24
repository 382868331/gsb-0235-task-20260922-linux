"""ec17 教学签名严格验签 —— 固定输入演示（真实计算，无网络、无随机源、无 sleep）。

运行：python demo.py

演示内容：
  1. 现场穷举 F_17 上的曲线点并核对基点阶；
  2. 用显式教学 nonce 对一条合成消息签名，打印编码并严格验真；
  3. 实际触发两个拒绝边界：篡改消息（SignatureMismatchError）
     与 s+19 模阶可塑性（ScalarOutOfRangeError，在边界被拒绝）；
  4. 会话层：会话 ID、nonce 预留→使用→作废状态机、请求 ID 幂等重放、
     同 nonce 签不同消息被拒且不回收、失败不留半更新、关闭后的阶段乱序。

警告：全部数据仅用于教学，私钥/nonce 都是写死的小整数，严禁用于真实场景。
"""

import hashlib
import time

import ec17


def enumerate_finite_points():
    """现场穷举（真实计算，不引用测试参考实现）。"""
    points = []
    for x in range(ec17.FIELD_PRIME):
        rhs = (x ** 3 + ec17.COEFF_A * x + ec17.COEFF_B) % ec17.FIELD_PRIME
        for y in range(ec17.FIELD_PRIME):
            if (y * y) % ec17.FIELD_PRIME == rhs:
                points.append((x, y))
    return points


def main():
    started = time.perf_counter()

    print("== ec17 椭圆曲线教学签名：严格验签演示 ==")
    print(
        f"曲线 y^2 = x^3 + {ec17.COEFF_A}x + {ec17.COEFF_B}"
        f" mod {ec17.FIELD_PRIME}；基点 G={ec17.GENERATOR}"
    )

    finite = enumerate_finite_points()
    print(f"[穷举] F_17 上有限点数 = {len(finite)}，加无穷远点共 "
          f"{len(finite) + 1} = 群阶 {ec17.GROUP_ORDER}")

    # --- 1. 合成签名与验真 --------------------------------------------------
    secret_key = 7          # 教学私钥（写死，禁止使用真实密钥）
    nonce = 13              # 教学 nonce（由调用方显式提供）
    message = b"ec17-schnorr-teaching"

    public_key = ec17.derive_public_key(secret_key)
    signature = ec17.sign(secret_key, message, nonce)
    encoded_r = ec17.encode_point(signature.r)
    encoded_p = ec17.encode_point(public_key)
    e_value = ec17.challenge(signature.r, public_key, message)
    encoded_sig = ec17.encode_signature(signature)

    digest = hashlib.sha256(encoded_r + encoded_p + message).hexdigest()
    print("\n-- 正常路径：合成签名验真 --")
    print(f"消息 message         = {message!r}")
    print(f"公钥 P = {secret_key}*G      = {public_key}，压缩编码 = {encoded_p.hex()}")
    print(f"承诺 R = {nonce}*G      = {signature.r}，压缩编码 = {encoded_r.hex()}")
    print(f"SHA256(R||P||m)      = {digest}")
    print(f"质询 e = digest mod 19 = {e_value}")
    print(f"应答 s               = {signature.s}，签名(2+1字节) = {encoded_sig.hex()}")
    print(f"验签 s*G == R + e*P  : {ec17.verify(message, public_key, signature.r, signature.s)}")

    # --- 2a. 实际触发：篡改消息 --------------------------------------------
    tampered = bytes((message[0],)) + message[1:-1] + b"h"  # 末字符 g -> h
    print("\n-- 拒绝边界 1：篡改最后一个字节 --")
    print(f"被篡改消息 = {tampered!r}")
    try:
        ec17.assert_verify(tampered, public_key, signature.r, signature.s)
    except ec17.SignatureMismatchError as exc:
        print(f"如预期拒绝（{type(exc).__name__}）：{exc}")
        print(f"verify() 布尔结果 = {ec17.verify(tampered, public_key, signature.r, signature.s)}")

    # --- 2b. 实际触发：s+19 模阶可塑性 --------------------------------------
    print("\n-- 拒绝边界 2：s+19 模阶可塑性 --")
    try:
        ec17.verify(message, public_key, signature.r, signature.s + ec17.GROUP_ORDER)
    except ec17.ScalarOutOfRangeError as exc:
        print(f"如预期在边界拒绝（{type(exc).__name__}）：{exc}")

    # --- 3. 会话层：ID / nonce 生命周期 / 请求幂等 --------------------------
    print("\n== 会话层：会话 ID + nonce 预留/使用/作废 + 请求幂等 ==")
    registry = ec17.SessionRegistry()
    session = registry.create_session("session-demo", secret_key)
    print(f"创建会话 session-demo，公钥 = {session.public_key}")

    # 阶段乱序：未预留先签名
    print("\n-- 阶段乱序：未预留 nonce 就签名 --")
    try:
        session.sign("req-early", message, nonce)
    except ec17.NonceNotReservedError as exc:
        print(f"如预期拒绝（{type(exc).__name__}）：{exc}")
        print(f"  失败后 nonce 状态 = {session.nonce_status(nonce)}（未登记、未预留）")

    # 正常路径：预留 -> 签名 -> used
    session.reserve_nonce(nonce)
    print(f"\n预留 nonce={nonce} 后状态 = {session.nonce_status(nonce)}")
    sess_sig = session.sign("req-001", message, nonce)
    print(f"请求 req-001 签名：R={sess_sig.r}, s={sess_sig.s}，"
          f"状态 -> {session.nonce_status(nonce)}")
    print(f"旧验签入口仍可用：{ec17.verify(message, session.public_key, sess_sig.r, sess_sig.s)}")

    # 请求幂等：同请求 ID + 同参数原样重放
    replayed = session.sign("req-001", message, nonce)
    print(f"同请求 ID 重放返回同一签名对象：{replayed is sess_sig}")
    # 同请求 ID + 不同参数 -> 冲突，状态不变
    print("-- 请求幂等冲突：req-001 换消息重放 --")
    try:
        session.sign("req-001", b"tampered-by-replay", nonce)
    except ec17.IdempotencyConflictError as exc:
        print(f"如预期拒绝（{type(exc).__name__}）：{exc}")
    print(f"  冲突后 nonce 仍为 {session.nonce_status(nonce)}，原重放仍返回同一对象："
          f"{session.sign('req-001', message, nonce) is sess_sig}")

    # 同一 nonce 签不同消息 -> NonceReuseError，不回收
    print("\n-- nonce 重用：同一 nonce 签不同消息 --")
    other_message = b"a-different-synthetic-message"
    try:
        session.sign("req-002", other_message, nonce)
    except ec17.NonceReuseError as exc:
        print(f"如预期拒绝（{type(exc).__name__}）：{exc}")
    print(f"  nonce 状态 = {session.nonce_status(nonce)}（不回收），尝试重新预留：")
    try:
        session.reserve_nonce(nonce)
    except ec17.NonceReservationError as exc:
        print(f"  如预期拒绝（{type(exc).__name__}）：{exc}")
    # 失败不登记请求 ID：req-002 签原消息仍可成功（确定性相同）
    same_again = session.sign("req-002", message, nonce)
    print(f"  req-002 未被失败占用，用它签原消息成功，签名一致："
          f"{(same_again.r, same_again.s) == (sess_sig.r, sess_sig.s)}")

    # 作废：另一个会话演示 reserved/revoked 路径
    print("\n-- nonce 作废（reserved -> revoked，作废不可撤销）--")
    session2 = registry.create_session("session-demo-2", secret_key)
    session2.reserve_nonce(5)
    session2.revoke_nonce(5)
    print(f"nonce=5 作废后状态 = {session2.nonce_status(5)}")
    try:
        session2.sign("req-x", message, 5)
    except ec17.NonceLifecycleError as exc:
        print(f"  作废 nonce 签名被拒（{type(exc).__name__}）：{exc}")
    try:
        session2.revoke_nonce(5)
    except ec17.NonceLifecycleError as exc:
        print(f"  重复作废被拒（{type(exc).__name__}）：{exc}")

    # 解析关系：若协议放任重用，sk = (s1-s2)/(e1-e2) mod 19 直接泄露私钥
    print("\n-- 为什么必须防重用：两条会话各签一条消息，代数解出私钥 --")
    sig_a = ec17.sign(secret_key, message, nonce)
    sig_b = ec17.sign(secret_key, other_message, nonce)
    e_a = ec17.challenge(sig_a.r, public_key, message)
    e_b = ec17.challenge(sig_b.r, public_key, other_message)
    recovered = ((sig_a.s - sig_b.s) * pow((e_a - e_b) % ec17.GROUP_ORDER,
                                           -1, ec17.GROUP_ORDER)) % ec17.GROUP_ORDER
    print(f"e1={e_a}, s1={sig_a.s}；e2={e_b}, s2={sig_b.s}")
    print(f"sk = (s1-s2)/(e1-e2) mod 19 = {recovered}，与真实私钥 {secret_key} "
          f"一致：{recovered == secret_key}")

    # 关闭与阶段乱序
    print("\n-- 会话关闭与注册表 --")
    print(f"在册会话：{registry.session_ids()}")
    registry.close_session("session-demo")
    print("关闭 session-demo 并注销")
    try:
        registry.get_session("session-demo")
    except ec17.SessionNotFoundError as exc:
        print(f"  再取回被拒（{type(exc).__name__}）：{exc}")
    try:
        session.sign("req-after-close", message, nonce)
    except ec17.SessionPhaseError as exc:
        print(f"  关闭后签名被拒（{type(exc).__name__}）：{exc}")
    print(f"  关闭后只读查询仍可用：nonce={nonce} 状态 = {session.nonce_status(nonce)}")
    # 关闭已注销，同 ID 可重新创建为全新会话
    rebuilt = registry.create_session("session-demo", secret_key)
    print(f"  同 ID 重建成功，旧 nonce 状态不复存在：{rebuilt.nonce_status(nonce)}")

    elapsed = time.perf_counter() - started
    print(f"\n演示完成，实际计算耗时 {elapsed:.3f} 秒（无 sleep、无预录结果）。")


if __name__ == "__main__":
    main()
