# 椭圆曲线教学签名的严格验签（ecc_teach）

为**离线密码工程教学**实现的可复用 Python 库：在小素数教学曲线上实现点加/倍点/
标量乘、最短压缩点编码，以及 Schnorr 风格教学签名的**严格验签**，并配套独立参考
穷举群表、必要单元测试、固定输入演示。

> ⚠️ **教学专用 / 不安全（TEACHING ONLY, NOT SECURE）**
> 曲线群只有 **19 个元素**，私钥空间仅 18 个非零值，任何人都能瞬间穷举；
> SHA-256 输出被折叠到 mod 19，碰撞平凡。本库**禁止**用于真实密钥、真实资产
> 或任何需要安全保障的场景。所有接口、模块与演示均显式标注教学不安全。
> 本库只实现本题契约的有限数学/协议子集，**不兼容、也不宣称兼容**任何行业
> 标准（不是 RFC 8032 / BIP-Schnorr / SEC1 的完整实现）。

## 运行环境与依赖

- **Python 3.14.7**（在 Linux 原生 CPython 3.14.7 下开发与验证）。
- **仅标准库**（`hashlib`、`math`、`unittest`、`typing`）。安装 Python 后
  **无需安装任何第三方依赖**。
- 完全离线：不访问网络、不需要账号/硬件/数据库/中间件/云 API/Docker；
  不读取、不写入任何真实密钥文件；不使用随机源（nonce 由测试/调用方显式给定）。

## 准确命令

在仓库根目录（本文件所在目录）执行：

```bash
# 运行全部必要测试（独立参考穷举 19×19 群表、19^3 结合律、签名全空间对照等）
python -m unittest discover -s tests -v

# 固定输入演示：1 个真实验真 + 3 个实际触发的拒绝边界，远小于 8 秒
python demo.py
```

## 固定的公开数据结构与域参数

曲线（固定、不可配置）：

```
E: y² = x³ + 2x + 2  (mod 17)
基点 G = (5, 1)，阶 n = 19（素数）
全群 = 18 个仿射点 + 1 个无穷远点 O
```

- `Point = Optional[tuple[int, int]]`：`None` 表示无穷远点 **O**，否则为 `(x, y)`。
- `Signature(s, r_encoding)`：不可变的 tuple 子类（可解包、可比较）。
  - `s`：响应标量，契约合法值 `0..18`；
  - `r_encoding`：点 R 的最短压缩编码（`bytes`）。

### 压缩点编码（最短形式）

- 仿射点：**恰好 2 字节** `prefix ‖ x`。
  - `prefix = 0x02` 表示 y 为偶数，`0x03` 表示 y 为奇数；
  - `x` 为单字节，合法值 `0..16`。
- 无穷远点：**恰好 1 字节** `0x00`，且仅在 `allow_infinity=True` 的编码/解码
  上下文中合法；验签上下文一律拒绝 O。
- 严格拒绝：非 `bytes`、空串/截断、长度 3 字节及以上（前导零或多余后缀，属
  **非最短编码**）、非法前缀、`x ≥ 17`（域外）、该 x 曲线上无点（非二次剩余）。

> **本曲线的一个事实**：三次式在 F17 上无根，即不存在 y=0 的点。因此每个有解
> x 的两个根 ±y 奇偶相反——把奇偶前缀翻到“另一侧”不是字节非法，而是唯一地
> **解码成逆点**。这样的输入能通过解码，但在签名方程 `sG=R+eP` 处被拒绝。

## 公开接口

所有名称可从顶层包 `ecc_teach` 导入；实现位于 `ecc_teach/core.py`。

| 接口 | 说明 |
|---|---|
| 常量 | `P_MOD=17`, `A_COEF=2`, `B_COEF=2`, `GENERATOR=(5,1)`, `ORDER=19`, `MAX_MESSAGE_BYTES=65536`, `PREFIX_EVEN/ODD`, `INFINITY_ENCODING` |
| `is_infinity(point)` | 是否为 O |
| `point_neg(point)` | 逆元：`-O=O`，`-(x,y)=(x,-y mod 17)` |
| `is_on_curve(point)` | 合法曲线点（含 O）返回 True，不抛异常 |
| `point_add(left, right)` | 点加（相同点自动走倍点公式，互逆返回 O） |
| `point_double(point)` | 倍点 2P |
| `scalar_mult(k, point)` | 双加标量乘；`k` 为精确非负 `int` |
| `encode_point(point, *, allow_infinity=False)` | 最短压缩编码 |
| `decode_point(data, *, allow_infinity=False)` | 严格解码，拒绝非最短/域外/错误结构 |
| `derive_public_key(d)` | 教学私钥标量 `d∈1..18` → 压缩公钥 `P=dG` |
| `challenge(R, P, message)` | `e = SHA256(encode(R) ‖ encode(P) ‖ message) mod 19` |
| `sign_scalar(d, message, nonce)` | **教学合成**：`R=kG`，`s=k+e·d mod19`；nonce 必须显式给定 |
| `verify_signature(pub_enc, message, signature)` | 严格验签：通过返回 `True`，否则抛 `InvalidSignatureError` |
| `is_signature_valid(...)` | 验签的布尔便捷形式（密码学无效→`False`，契约类型错误仍抛出） |

### 严格验签顺序与原因码（`InvalidSignatureError.reason`）

按以下顺序暴露**第一个**失败：

1. `s_range`：`s` 不是精确 int/为 bool/不在 `0..18`（**s+19、s+38 等模等价
   可塑性一律拒绝，绝不静默取模**）；
2. `public_key_encoding`：公钥编码字节非法（非最短/域外/无点）；
3. `public_key_infinity`：公钥为 O；
4. `r_encoding`：R 编码字节非法；
5. `r_infinity`：R 为 O；
6. 计算 `e=SHA256(R‖P‖message) mod 19`；
7. `equation_fail`：`sG ≠ R + eP`。

## 输入契约与错误语义

- **数值输入拒绝 NaN/带符号 Infinity**：抛 `NonFiniteNumberError`；有限
  `float` 也不做隐式取整，抛 `StrictTypeError`。
- **整数参数拒绝 `bool`**：`True/False` 即使是 `int` 子类也按类型错误拒绝。
- **不静默纠正**：越界、错误类型、错误结构都抛可定位的异常；消息必须是精确
  `bytes`（`str`/`bytearray` 拒绝，需调用方显式编码）。
- 异常层级（`ecc_teach/errors.py`）：
  - `ECCTeachError`（共同基类）
    - `StrictTypeError`（同时是 `TypeError`）
    - `NonFiniteNumberError`（同时是 `ValueError`）
    - `InvalidPointError`、`EncodingError`、`MessageTooLongError`、
      `InvalidSignatureError`（同时是 `ValueError`）。
- 本库无批次/有状态的可变操作：`Signature` 不可变，函数均无隐藏副作用，
  因此不存在“部分变更”；签名合成/验签不修改任何入参或全局状态。
- 本库没有“搜索预算”类过程；数学上“无解”（如该 x 无曲线点、逆元不存在）
  直接作为可定位错误，与任何预算耗尽情形无关。

### 输入上限

| 量 | 上限/范围 | 越界行为 |
|---|---|---|
| 标量 `d`（私钥教学标量） | `1..18` | `ValueError`（0/19/负数拒绝） |
| nonce `k` | `1..18`（0/19 会使 R=O，拒绝） | `ValueError` |
| 验签 `s` | `0..18` | `InvalidSignatureError(s_range)` |
| 坐标 x, y | `0..16` | `InvalidPointError`/`EncodingError` |
| 点编码长度 | 仿射 2 字节 / O 1 字节 | `EncodingError`（非最短拒绝） |
| `message` | 精确 `bytes`，长度 ≤ `65536` | `StrictTypeError`/`MessageTooLongError` |

## 误差口径（无浮点）

本库全部数学都是 **F17 / Z19 上的精确整数模运算**，点坐标、标量、哈希整数
均为精确 `int`，模逆用精确的扩展欧几里得（`pow(a,-1,17)`）。**没有任何浮点
输出，因此不存在数值误差、不需要也不使用任何容差**；不会用“宽容差”掩盖边界
错误。唯一接触 `float` 的地方是输入校验：显式拒绝 NaN/Infinity 及一切
`float`。

## 设计取舍

- **显式教材公式**：点加/倍点用斜率公式直接实现，标量乘用双加（非恒定时间）。
  群仅 19 点，恒定时间无意义；可读性优先。
- **最短编码严格化**：x 固定单字节（域小于 256），任何多余字节即非最短，立即
  拒绝；奇偶前缀直接在枚举的 y 根上匹配。
- **验签失败给稳定原因码**：区分“调用契约错误”（类型/长度，抛
  `StrictTypeError` 等）与“密码学上无效”（抛 `InvalidSignatureError`，携带
  `reason`），便于教学定位。
- **合成签名仅为教学/测试**：`sign_scalar` 强制显式 nonce，不提供随机数、
  不读写密钥文件。
- **独立参考独立成档**：`tests/reference.py` 不导入被测库，仅凭题面常量重新
  枚举点、独立实现公式、独立建 19×19 加法表与独立验签。测试期望值来自该参考
  或硬编码向量；“编码→解码往返一致”只作为补充断言。

## 测试覆盖

`python -m unittest discover -s tests -v`（51 个用例）：

- 独立穷举全部曲线点与完整加法表，穷举验证封闭性、同一律、逆元唯一
  （`-(x,y)=(x,-y)`、`-O=O`）、**19³ 组结合律**、交换律、离散对数表一致、
  素数阶无真子群；
- 被测核心的点加/倍点/标量乘/逆元与独立加法表**逐格交叉**；
- 无穷远点行为、硬编码 1G..19G 序列；
- 编码：全部 18 点对照独立参考、非最短编码、域外 x、无点 x、错误结构、
  翻转奇偶解码为逆点的本曲线事实；
- 签名：硬编码 SHA-256 挑战向量（`d=7,k=11`，锁定原语拼接与字节序）、
  全 `d,k∈1..18 × 多条消息` 网格与独立参考互验、**全 342 候选空间判定一致**、
  每消息恰好 18 个合法签名；
- 拒绝边界：**s+19 可塑性**、错误奇偶（→逆点→方程失败）、R/P 为无穷远、
  非最短/域外编码、消息篡改、s 偏移、R 换成别的合法点、错误公钥；
- 严格输入：bool 当 int、NaN/Infinity、有限 float、其它类型、负数/越界、
  消息类型与长度上限边界。

## 已知限制

1. 仅支持这一条固定曲线与这一种固定编码/Schnorr 教学变体，不可参数化。
2. 不防时序侧信道（非恒定时间）；教学场景无真实密钥。
3. 不实现签名 DER/字节序列化标准、证书、密钥文件或随机 nonce 生成。
4. 不提供批处理/异步/网络接口；不扩展为 CLI 产品、网站或服务。

## 仓库结构

```
ecc_teach/
  __init__.py     # 公开接口导出与教学不安全声明
  core.py         # 曲线点运算、压缩编码、Schnorr 合成/严格验签
  errors.py       # 固定错误语义与异常层级
tests/
  reference.py    # 独立参考（不导入被测库）：枚举/群表/独立验签
  test_group.py   # 群运算与穷举群表交叉
  test_encoding.py# 压缩编码与严格输入
  test_signature.py# 签名/严格验签与全部拒绝边界
demo.py           # 固定输入现场计算演示
requirements.txt  # 无第三方依赖（仅注释说明）
README.md
```
