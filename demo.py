"""ec17 教学签名严格验签 —— 固定输入演示（真实计算，无网络、无随机源、无 sleep）。

运行：python demo.py

演示内容：
  1. 现场穷举 F_17 上的曲线点并核对基点阶；
  2. 用显式教学 nonce 对一条合成消息签名，打印编码并严格验真；
  3. 实际触发两个拒绝边界：篡改消息（SignatureMismatchError）
     与 s+19 模阶可塑性（ScalarOutOfRangeError，在边界被拒绝）。
  4. 教学批验签：全有效批、两个错误相互抵消的必测反例（聚合通过但
     exact 逐项定位）、非法编码整批拒绝（带索引），以及共享倍点表
     与重复调用 verify 的实际点加次数对比。

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

    # --- 3. 教学批验签 ------------------------------------------------------
    print("\n-- 批验签：全有效批 --")
    batch_keys = [7, 5]
    entries = []
    for i in range(36):
        sk = batch_keys[i % 2]
        msg = b"batch-demo-%02d" % i
        sig = ec17.sign(sk, msg, (i % 18) + 1)
        entries.append(ec17.BatchEntry(msg, ec17.derive_public_key(sk),
                                       sig.r, sig.s))
    coeffs = [(i % 18) + 1 for i in range(len(entries))]
    report = ec17.batch_verify(entries, coeffs, exact=True)
    print(f"36 项批：aggregate_ok={report.aggregate_ok}, "
          f"all_valid={report.all_valid}, invalid_indices={report.invalid_indices}")

    print("\n-- 批验签反例：两个错误签名相互抵消 --")
    sig_a = ec17.sign(7, b"cancel-a", 13)
    sig_b = ec17.sign(5, b"cancel-b", 4)
    bad_a = ec17.BatchEntry(b"cancel-a", ec17.derive_public_key(7),
                            sig_a.r, (sig_a.s + 1) % 19)   # 误差 +1
    bad_b = ec17.BatchEntry(b"cancel-b", ec17.derive_public_key(5),
                            sig_b.r, (sig_b.s - 1) % 19)   # 误差 -1，恰好抵消
    for label, entry in (("bad_a", bad_a), ("bad_b", bad_b)):
        ok = ec17.verify(entry.message, entry.public_key, entry.r, entry.s)
        print(f"逐项验签 {label}: verify -> {ok}（单独无效）")
    cancel_report = ec17.batch_verify([bad_a, bad_b], [1, 1], exact=True)
    print(f"批报告：aggregate_ok={cancel_report.aggregate_ok}"
          "  <- 聚合等式被抵消骗过，不能当安全结论")
    print(f"批报告：all_valid={cancel_report.all_valid}, "
          f"invalid_indices={cancel_report.invalid_indices}  <- exact 逐项定位")

    print("\n-- 批验签：非法编码整批拒绝（带索引） --")
    good_enc = (b"m", ec17.encode_point(ec17.derive_public_key(7)),
                ec17.encode_point(sig_a.r), ec17.encode_scalar(sig_a.s))
    bad_enc = (b"m2", b"\x02\x11", b"\x02\x05", b"\x03")  # x=17 域外
    try:
        ec17.batch_verify_encoded([good_enc, bad_enc], [1, 1])
    except ec17.BatchItemError as exc:
        print(f"如预期整批拒绝（{type(exc).__name__}, index={exc.index}）：{exc}")

    print("\n-- 点加次数对比：exact 批验签 vs 重复调用 verify --")
    ec17.clear_multiples_cache()
    ec17.reset_point_add_counter()
    ec17.batch_verify(entries, coeffs, exact=True)
    batch_adds = ec17.point_add_count()
    ec17.reset_point_add_counter()
    for entry in entries:
        ec17.verify(entry.message, entry.public_key, entry.r, entry.s)
    repeated_adds = ec17.point_add_count()
    print(f"36 项 exact 批验签点加次数 = {batch_adds}，"
          f"重复 verify = {repeated_adds}（共享倍点表摊销）")

    elapsed = time.perf_counter() - started
    print(f"\n演示完成，实际计算耗时 {elapsed:.3f} 秒（无 sleep、无预录结果）。")


if __name__ == "__main__":
    main()
