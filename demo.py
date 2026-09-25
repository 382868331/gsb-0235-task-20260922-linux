"""ec17 教学签名严格验签 —— 固定输入演示（真实计算，无网络、无随机源、无 sleep）。

运行：python demo.py

演示内容：
  1. 现场穷举 F_17 上的曲线点并核对基点阶；
  2. 用显式教学 nonce 对一条合成消息签名，打印编码并严格验真；
  3. 实际触发两个拒绝边界：篡改消息（SignatureMismatchError）
     与 s+19 模阶可塑性（ScalarOutOfRangeError，在边界被拒绝）。

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

    # --- 3. 教学批验签：聚合通过 ≠ 逐项有效 ----------------------------------
    print("\n-- 教学批验签（aggregate_ok 不是安全结论） --")
    keys = (3, 7, 11)
    entries = []
    for i in range(12):
        sk = keys[i % 3]
        sig = ec17.sign(sk, f"batch-{i}".encode(), (i % 18) + 1)
        entries.append(ec17.BatchEntry(f"batch-{i}".encode(),
                                       ec17.derive_public_key(sk), sig.r, sig.s))
    coeffs = [(i % 18) + 1 for i in range(12)]
    report = ec17.batch_verify(entries, coeffs, exact=True)
    print(f"12 条合法签名：aggregate_ok={report.aggregate_ok}, "
          f"all_valid={report.all_valid}, invalid_indices={report.invalid_indices}, "
          f"点加次数={report.point_additions}")

    # 抵消反例：两条各自无效（s 分别 +1/-1，缺陷互为相反数），聚合却通过
    e1, e2 = entries[0], entries[1]
    bad1 = ec17.BatchEntry(e1.message, e1.public_key, e1.r, (e1.s + 1) % 19)
    bad2 = ec17.BatchEntry(e2.message, e2.public_key, e2.r, (e2.s - 1) % 19)
    print(f"逐项验签 bad1={ec17.verify(e1.message, e1.public_key, e1.r, bad1.s)}, "
          f"bad2={ec17.verify(e2.message, e2.public_key, e2.r, bad2.s)}（都无效）")
    cancel = ec17.batch_verify([bad1, bad2], [1, 1], exact=True)
    print(f"抵消对批验签：aggregate_ok={cancel.aggregate_ok}（会误导！）, "
          f"exact 后 all_valid={cancel.all_valid}, "
          f"invalid_indices={cancel.invalid_indices}")

    # 非法编码整批拒绝并给出下标
    try:
        ec17.batch_verify_encoded(
            [(b"m", ec17.encode_point(public_key), b"\x00", b"\x01")], [1])
    except ec17.BatchItemError as exc:
        print(f"非法编码整批拒绝（index={exc.index}）：{exc}")

    elapsed = time.perf_counter() - started
    print(f"\n演示完成，实际计算耗时 {elapsed:.3f} 秒（无 sleep、无预录结果）。")


if __name__ == "__main__":
    main()
