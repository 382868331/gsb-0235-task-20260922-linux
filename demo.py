"""ec17 教学签名严格验签 —— 固定输入演示（真实计算，无网络、无随机源、无 sleep）。

运行：python demo.py

演示内容：
  1. 现场穷举 F_17 上的曲线点并核对基点阶；
  2. 用显式教学 nonce 对一条合成消息签名，打印编码并严格验真；
  3. 实际触发两个拒绝边界：篡改消息（SignatureMismatchError）
     与 s+19 模阶可塑性（ScalarOutOfRangeError，在边界被拒绝）；
  4. 有状态签名会话：会话 ID、nonce 预留→使用→作废的完整生命周期，
     重复请求幂等、同 nonce 签不同消息被拒、阶段乱序被拒、作废不回收。

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

    # --- 3. 有状态会话：会话 ID + nonce 预留/使用/作废 ----------------------
    print("\n-- 有状态会话：nonce 生命周期与幂等 --")
    session = ec17.SigningSession(b"demo-session-001", secret_key)
    print(f"会话 ID = {session.session_id!r}，公钥 P = {session.public_key}")

    session_nonce = 5
    session_message = b"session-bound-message"
    print(f"[阶段1] 预留 nonce={session_nonce} 并绑定消息 {session_message!r}："
          f" reserve -> {session.reserve_nonce(session_nonce, session_message)}")
    print(f"         重复预留同一(nonce,消息)幂等：reserve -> "
          f"{session.reserve_nonce(session_nonce, session_message)}（False=无操作）")
    sig1 = session.sign(session_message, session_nonce)
    sig2 = session.sign(session_message, session_nonce)
    print(f"[阶段2] 首次签名 s={sig1.s}；重复同一请求返回同一对象：{sig1 is sig2}")
    print(f"         nonce 状态 = {session.nonce_status(session_nonce)}，"
          f"已使用列表 = {session.used_nonces()}")

    # 3a. 实际触发：同一 nonce 签不同消息
    print("\n-- 会话拒绝 1：同一 nonce 签不同消息 --")
    try:
        session.sign(b"a-totally-different-message", session_nonce)
    except ec17.NonceReuseError as exc:
        print(f"如预期拒绝（{type(exc).__name__}）：{exc}")
    # 解析关系现场核算：两条同 nonce 签名即可解出私钥（教学风险演示）。
    e1 = ec17.challenge(sig1.r, public_key, session_message)
    other_message = b"a-totally-different-message"
    raw_other = ec17.sign(secret_key, other_message, session_nonce)
    e2 = ec17.challenge(raw_other.r, public_key, other_message)
    recovered = ((sig1.s - raw_other.s) * pow(e1 - e2, -1, ec17.GROUP_ORDER)) % ec17.GROUP_ORDER
    print(f"         解析核对 sk=(s1-s2)/(e1-e2) mod 19 = {recovered}"
          f"（真实私钥 {secret_key}，nonce 重用即泄露）")
    print(f"         被拒后原请求幂等重放仍可用："
          f"{session.sign(session_message, session_nonce) is sig1}")

    # 3b. 实际触发：阶段乱序（未预留就签名）
    print("\n-- 会话拒绝 2：阶段乱序（nonce 未预留就签名）--")
    try:
        session.sign(session_message, 11)
    except ec17.NonceNotReservedError as exc:
        print(f"如预期拒绝（{type(exc).__name__}）：{exc}")

    # 3c. 实际触发：作废不回收（失败也不回收为可用）
    print("\n-- 会话拒绝 3：作废是终态，不回收为可用 --")
    session.reserve_nonce(8, b"to-be-voided")
    session.void_nonce(8)
    print(f"nonce=8 作废后状态 = {session.nonce_status(8)}，"
          f"作废列表 = {session.voided_nonces()}")
    try:
        session.reserve_nonce(8, b"to-be-voided")
    except ec17.NonceVoidedError as exc:
        print(f"如预期拒绝重新预留（{type(exc).__name__}）：{exc}")

    # 3d. 边界：空会话 ID 在构造时即被拒绝（不留半成品对象）
    print("\n-- 会话边界：空会话 ID / nonce=0 --")
    try:
        ec17.SigningSession(b"", secret_key)
    except ec17.InvalidSessionIdError as exc:
        print(f"如预期拒绝空会话 ID（{type(exc).__name__}）：{exc}")
    try:
        session.reserve_nonce(0, b"bad-nonce")
    except ec17.InvalidNonceError as exc:
        print(f"如预期拒绝 nonce=0（{type(exc).__name__}）：{exc}")
    print(f"         非法输入后会话状态不变：已用 {session.used_nonces()}，"
          f"已作废 {session.voided_nonces()}")

    elapsed = time.perf_counter() - started
    print(f"\n演示完成，实际计算耗时 {elapsed:.3f} 秒（无 sleep、无预录结果）。")


if __name__ == "__main__":
    main()
