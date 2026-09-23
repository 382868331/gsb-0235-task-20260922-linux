#!/usr/bin/env python3
"""固定输入演示：合成 Schnorr 风格教学签名，真实计算并严格验签。

运行：python demo.py（约 8 秒内完成，无网络、无文件 IO、无 sleep、
无预录结果；所有值现场计算）。

⚠️ 教学不安全（TEACHING ONLY）：曲线群只有 19 个点，私钥空间 18 个值，
禁止用于真实密钥或真实场景。
"""

from __future__ import annotations

import time

from ecc_teach import (
    A_COEF,
    B_COEF,
    GENERATOR,
    ORDER,
    P_MOD,
    InvalidSignatureError,
    Signature,
    challenge,
    decode_point,
    derive_public_key,
    encode_point,
    point_add,
    scalar_mult,
    sign_scalar,
    verify_signature,
)

# --- 固定的合成输入（确定性，禁止随机数/密钥文件） -------------------------
SECRET_SCALAR = 7          # 教学私钥标量 d ∈ 1..18
NONCE = 11                 # 显式提供的签名 nonce k ∈ 1..18
MESSAGE = b"offline-ecc-teaching-demo"
TAMPERED_MESSAGE = b"offline-ecc-teaching-DEMO"  # 仅最后一个字母大小写改动


def banner(title: str) -> None:
    print()
    print("=" * 68)
    print(title)
    print("=" * 68)


def main() -> None:
    started = time.perf_counter()

    print("椭圆曲线教学签名严格验签 —— 固定输入现场计算演示")
    print(f"曲线: y^2 = x^3 + {A_COEF}x + {B_COEF} mod {P_MOD}; "
          f"G={GENERATOR}, 阶 n={ORDER}")
    print("警告: 仅用于教学（群仅 19 个点），不安全，禁止真实密钥/真实场景。")

    # --- 1. 正常路径：合成签名并严格验签 -----------------------------------
    banner("[1] 正常结果：合成签名 -> 严格验签通过")
    public_enc = derive_public_key(SECRET_SCALAR)
    signature = sign_scalar(SECRET_SCALAR, MESSAGE, NONCE)

    r_point = decode_point(signature.r_encoding)
    public_point = decode_point(public_enc)
    e = challenge(r_point, public_point, MESSAGE)
    lhs = scalar_mult(signature.s, GENERATOR)
    rhs = point_add(r_point, scalar_mult(e, public_point))

    print(f"message          = {MESSAGE!r}")
    print(f"d={SECRET_SCALAR}, k={NONCE}（均为固定合成输入）")
    print(f"公钥 P=dG        = {public_point}, 压缩编码 = {public_enc!r}")
    print(f"R=kG             = {r_point}, 压缩编码 = {signature.r_encoding!r}")
    print(f"e=SHA256(R‖P‖m) mod {ORDER} = {e}（现场哈希计算，非预录）")
    print(f"s=(k+e*d) mod {ORDER}       = {signature.s}")
    print(f"方程两边现场重算: sG = {lhs}")
    print(f"                  R+eP = {rhs}")
    result = verify_signature(public_enc, MESSAGE, signature)
    print(f"verify_signature -> {result}")
    assert result is True and lhs == rhs

    # --- 2. 边界一：消息被篡改，编码全部合法，方程必须失败 ------------------
    banner("[2] 拒绝边界：消息篡改（equation_fail）")
    print(f"原消息 = {MESSAGE!r}")
    print(f"篡改后 = {TAMPERED_MESSAGE!r}")
    try:
        verify_signature(public_enc, TAMPERED_MESSAGE, signature)
    except InvalidSignatureError as exc:
        e2 = challenge(r_point, public_point, TAMPERED_MESSAGE)
        print(f"篡改消息后 e 变为 {e2}（原值 {e}），方程不再成立")
        print(f"如预期拒绝：{type(exc).__name__}: reason={exc.reason}")
    else:
        raise AssertionError("篡改消息竟然验签通过，库存在严重缺陷")

    # --- 3. 边界二：s+19 模等价可塑性，必须在范围检查处拒绝 ----------------
    banner("[3] 拒绝边界：s+19 可塑性（s_range，不静默取模）")
    malleable = Signature(signature.s + ORDER, signature.r_encoding)
    print(f"原 s={signature.s}；伪造签名使用 s={malleable.s}（同模 19 等价）")
    try:
        verify_signature(public_enc, MESSAGE, malleable)
    except InvalidSignatureError as exc:
        print(f"如预期拒绝：{type(exc).__name__}: reason={exc.reason}")
    else:
        raise AssertionError("s+19 竟然被接受")

    # --- 4. 边界三：非最短编码（合法两字节后追加 0x00） --------------------
    banner("[4] 拒绝边界：非最短点编码（r_encoding）")
    bloated = Signature(signature.s, signature.r_encoding + b"\x00")
    print(f"R 编码由 {signature.r_encoding!r} 被改成 {bloated.r_encoding!r}")
    try:
        verify_signature(public_enc, MESSAGE, bloated)
    except InvalidSignatureError as exc:
        print(f"如预期拒绝：{type(exc).__name__}: reason={exc.reason}")
    else:
        raise AssertionError("非最短编码竟然被接受")

    elapsed = time.perf_counter() - started
    print()
    print("-" * 68)
    print(f"演示结束：1 个验真通过 + 3 个实际触发的拒绝边界；耗时 {elapsed*1000:.1f} ms。")
    print("完整验证（含穷举 19^3 群表交叉核对）请运行：")
    print("    python -m unittest discover -s tests -v")


if __name__ == "__main__":
    main()
