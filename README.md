# ec17 — 椭圆曲线教学签名的严格验签（仅教学，不安全）

为离线密码工程教学实现的可复用库：在小素域椭圆曲线
**y² = x³ + 2x + 2 (mod 17)** 上实现点加/倍乘、压缩点编码，以及一个
Schnorr 风格教学签名的**严格验签**。

> ⚠️ **教学专用，不提供任何安全性。** 群只有 19 个元素，私钥空间可瞬间穷举；
> nonce 由调用方显式给定且不防重用；**禁止使用真实密钥/密钥文件**。
> 本库只实现题面契约的有限数学/协议子集，**不兼容也不宣称兼容** RFC 6979、
> secp256k1、FIPS 186 等任何行业标准。

## 运行环境

- Python **3.14.7**（Linux 原生验证；仅使用标准库 `hashlib`、`dataclasses`、`math`、`unittest`）
- **无需安装任何第三方依赖**，安装 Python 后即可运行
- 核心、测试、演示全部**离线**：不联网、不需要账号/硬件/数据库/中间件/云 API/Docker
- 示例数据由仓库内确定性代码生成，无随机源、无外部附件

## 准确命令

```bash
./.venv/bin/python -m unittest discover -s tests -v   # 运行必要测试（80 个，约 0.2 秒）
python demo.py                                        # 固定输入演示（约 0.04 秒，远低于 90 秒）
```

## 公开数据结构

| 名称 | 含义 |
|---|---|
| `Point` | 有限点，类型 `tuple[int, int]`，即 `(x, y)`，x,y ∈ 0..16 |
| `INFINITY` | 无穷远点（群单位元），用 `None` 表示 |
| `Signature` | 不可变 dataclass：`r: Point`、`s: int`、`message: bytes` |

曲线常量：`FIELD_PRIME=17`、`COEFF_A=2`、`COEFF_B=2`、`GROUP_ORDER=19`、
`GENERATOR=(5,1)`、`MAX_MESSAGE_BYTES=65535`。

曲线上恰有 18 个有限点，加上无穷远点共 19 个；G 是阶为 19 的生成元。

## 接口

### 群运算（`ec17/_curve.py`）

- `is_on_curve(point) -> bool`：无穷远返回 `False`；坐标域外返回 `False`；
  坐标类型非法抛 `TypeValidationError`。
- `point_neg(point)`：负点；`-O = O`。
- `point_add(p, q)`：点加（覆盖单位元、互逆点 P+(-P)=O、倍点切线）。
- `scalar_mul(k, point)`：双加法标量乘；`k` 必须是 **0..18** 的整数（`k=0` → O），
  不做隐式模 19 约化。

### 编码（`ec17/_encoding.py`，SEC1 风格的固定长度教学子集）

- 点编码：无穷远 → `00`（1 字节）；有限点 (x,y) → `prefix || x`（2 字节），
  `02` 表示 y 偶、`03` 表示 y 奇，x 为单字节。
- `encode_point(point) -> bytes`
- `decode_point(data, *, allow_infinity=True)`：严格解码。
- 标量：`encode_scalar(n)` / `decode_scalar(data, *, name="scalar")`，0..18 各 1 字节。

### Schnorr 教学签名（`ec17/_schnorr.py`）

- `derive_public_key(secret_key) -> Point`，`secret_key ∈ 1..18`。
- `sign(secret_key, message: bytes, nonce) -> Signature`，**nonce 由调用方显式
  提供**（∈ 1..18，0 被禁止），不读随机源、不读密钥文件。
- `challenge(r, public_key, message) -> int`：
  `e = SHA256( encode(R) ∥ encode(P) ∥ message ) mod 19`。
- `s = (nonce + e·secret_key) mod 19`。
- 严格验签：
  - `verify(message, public_key, r, s) -> bool`
  - `assert_verify(message, public_key, r, s) -> None`（等式失败抛异常）
  - `verify_encoded(message, public_key_enc, r_enc, s_enc) -> bool`（字节入口）
  - `encode_signature(sig) -> bytes`（固定 3 字节：2 字节 R + 1 字节 s）、
    `decode_signature(data, message) -> Signature`

验签要求：**s ∈ 0..18；R、P 都不能是无穷远点且必须在曲线上**。
结构/范围非法抛对应可定位异常；仅“结构合法但等式 `s·G = R + e·P` 不成立”时
`verify` 返回 `False`（`assert_verify` 抛 `SignatureMismatchError`）。

### 教学批验签（`ec17/_batch.py`，仅教学，不安全）

- `BatchEntry(message, public_key, r, s)`：一条待验记录（也接受同序四元组）。
- `batch_verify(entries, coefficients, *, exact=False) -> BatchReport`：
  先逐项严格校验点/标量/消息，再由**调用方提供的非零域系数**
  （`coefficients[i] ∈ 1..18`，0 被禁止——零系数会把该项静默剔除）检查加权
  聚合等式 `(Σ aᵢsᵢ)·G == Σ aᵢRᵢ + Σ (aᵢeᵢ)·Pᵢ`。
- `batch_verify_encoded(encoded_entries, coefficients, *, exact=False)`：
  编码入口，每项 `(message, public_key_enc, r_enc, s_enc)` 先按单条规则严格
  解码；**非法编码整批拒绝**，抛 `BatchItemError`（`.index` 给出下标）。
- `bisect_aggregate_candidates(entries, coefficients)`：聚合失败批次的二分
  **候选**定位；聚合通过的子组也可能藏有抵消，结果不能替代 exact。
- `BatchReport` 字段：`size`、`aggregate_ok`、`exact`、`all_valid`、
  `invalid_indices`、`point_additions`（实际群加法次数，教学度量）。

**报告语义（关键）**：`aggregate_ok` 只说明加权等式成立。小群上错误签名的
缺陷可能相互抵消（测试里有“两条各自无效但聚合通过”的必测反例），因此
**`aggregate_ok=True` 不是安全结论**。只有 `exact=True` 时库才用共享倍点表
做确定性的逐项确认，`all_valid` 与按输入序的 `invalid_indices` 才有效；
非 exact 模式下二者为 `None`（未知）。exact 会检查**所有**项，包括聚合
通过的子组——抵消对藏在那里也会被逐项发现。

**缓存纪律**：共享倍点表只缓存公开点（G 与各公钥 P）的 0..18 倍，按批内
首次出现去重；消息挑战 e 逐项重算，绝不跨输入复用；R 每项唯一，不建表，
用计数双加。空批合法（`aggregate_ok=True`，`all_valid=True`）。

## 错误语义（`ec17/_errors.py`）

所有异常继承 `EC17Error`；类型错误同时是内置 `TypeError`。消息一律带参数名。

- 类型：`TypeValidationError`（拒绝 **bool 冒充整数**、拒绝 float，
  尤其拒绝 **NaN/±Infinity**）、`MessageTypeError`。
- 点：`CoordinateOutOfDomainError`（坐标不在 0..16）、`PointNotOnCurveError`
  （域内但不满足方程）、`PointAtInfinityError`。
- 编码：`EmptyEncodingError`、`TruncatedEncodingError`、
  `InvalidEncodingPrefixError`、`OutOfDomainEncodingError`（点 x≥17 / 标量≥19）、
  `NonShortestEncodingError`（任何尾随字节、`00` 后携带字节）。
- 签名：`ScalarOutOfRangeError`、`SignatureMismatchError`、
  `InvalidSecretKeyError`、`InvalidNonceError`、`MessageTooLongError`。
- 批验签：`BatchError`、`BatchLengthMismatchError`、`BatchTooLargeError`、
  `InvalidCoefficientError`（越界或零系数）、`BatchItemError`
  （携带 `.index`，整批拒绝，无部分通过）。

设计原则：非法输入**报错而非静默纠正**；不存在“部分成功”的有状态变更
（所有运算均为纯函数）；本库没有“搜索预算”类算法，也不区分预算耗尽/无解。

### 错误奇偶前缀

翻转奇偶前缀（`02↔03`）本身**不是**编码错误——它规范地解码为原点的负点
（-R），随后因验签等式不成立被拒绝。这与“非最短/域外编码”是两类不同问题。

### s+19 可塑性

数学上 `(s+19)·G = s·G`（模群阶）客观成立，但本协议在**输入边界**直接拒绝
任何越界标量：`s=19` 抛 `ScalarOutOfRangeError`，字节 `0x13` 抛
`OutOfDomainEncodingError`，不做隐式约化。

## 输入上限（接口边界）

- 点坐标 x,y：整数，0..16；群标量（s / scalar_mul 的 k）：0..18。
- 私钥：1..18；签名 nonce：1..18。
- 消息：`bytes`，长度 0..`MAX_MESSAGE_BYTES`(=65 535) 字节；`str` 不隐式编码。
- 编码长度：点 1 或 2 字节、标量恰 1 字节、签名帧恰 3 字节。
- 批验签：批大小 0..`MAX_BATCH_SIZE`(=4096)；系数与批等长，每个 ∈ 1..18。
- 所有整数参数拒绝 `bool`、`float`（含 NaN/Infinity）。

## 浮点与误差口径

核心算法只做**整数模运算**，代码路径中没有浮点结果，因此不存在浮点误差或
容差问题，也不以宽容差掩盖边界。唯一接触 `math` 的地方是用 `math.isfinite`
来**拒绝** NaN/Infinity 输入。

## 设计取舍

- 无穷远点用 `None` 而不是引入专门类，贴合教学公式，且让“R/P 不能无穷”的
  检查显式可见。
- 坐标只有一个字节（域为 17），编码刻意采用固定长度，使“非最短编码”有
  明确、可机械判定的含义（任何多余尾随字节即拒绝）。
- 验签对“结构非法”与“等式不成立”分别处理：前者抛异常（可定位），后者
  返回 `False`，避免把篡改误报成程序错误。
- 群运算在每个入口重复做点校验而非只在边界校验，教学上保证任何组合调用
  都不可能处理非法点；曲线极小，性能无关紧要。

## 测试与独立性

`tests/reference.py` 是**独立参考实现，绝不 import 被测核心**（有 AST 测试
强制保证），并用两条互相独立的路线给出期望值：
(1) 朴素仿射公式 + 重复相加；(2) 枚举 G 的全部倍数构建离散对数指数表，
群运算退化为指数的整数加法。

测试覆盖：穷举 19×19 全加法表与 19³ 全三元组结合律、点集基数、G 的阶、
无穷远单位元、逆点、交换/结合律；编码的空/截断/非法前缀/域外/非最短/
错误奇偶；签名 324 组 (私钥×nonce) 对独立参考的全量比对、s=0 合法签名、
篡改消息、错误公钥、翻转 R 奇偶、**s+19 可塑性在边界被拒**、R/P 无穷远与
不在曲线上、消息类型与长度上限、3 字节签名帧的各类畸形。
批验签测试覆盖：全合法批（exact/非 exact）、空批、四元组输入、
**两条单独无效但聚合抵消的必测反例**（aggregate_ok=True 而 exact 给出
(0, 1)，并用独立参考确认两条各自无效）、抵消对藏入聚合通过的大批仍被
exact 逐项发现、单条无效破坏聚合、结构/编码非法整批拒绝且下标准确、
零系数/越界系数/长度不匹配/bool 系数拒绝、二分候选定位与不可缩小情形、
以及共享倍点表的实际点加次数低于逐项重复调用 `verify` 的对比。
编解码往返一致只作为**补充**断言，不作为期望值来源。

## demo.py

`python demo.py` 现场穷举曲线点、核对阶，用固定的 `secret_key=7, nonce=13,
message=b"ec17-schnorr-teaching"` 真实生成并验证一个签名（打印 R/P 编码、
SHA256、e、s 与验签结果），**实际触发**两个拒绝边界（篡改消息、`s+19`），
并演示教学批验签：12 条合法签名的 exact 报告、两条各自无效但聚合抵消的
反例（`aggregate_ok=True` 的误导性与 exact 的逐项定位）、非法编码整批拒绝
带下标。不含 `sleep`，不使用预录结果，也不做压力测试（远低于 90 秒）。

## 已知限制

- 仅支持这一条 17 阶小曲线与上述固定协议，不支持任意曲线参数、随机 nonce、
  DER/SEC1 多字节整数编码或任何标准序列化。
- 批验签的聚合等式在小群上可被“缺陷抵消”欺骗；`aggregate_ok` 绝不能当作
  安全结论，逐项结论只能来自 exact 模式。二分定位只给候选。
- nonce 完全由调用方负责；重用 nonce 会直接泄露私钥（这正是教学要演示的风险）。
- 不提供任何侧信道防护（标量乘非常量时间）；在 19 元素群上也无安全可言。
- 无版本化/前向兼容承诺：这是一次性教学交付。

## 目录

```
ec17/            可导入库
  __init__.py      公共接口导出
  _errors.py       错误类型与语义
  _curve.py        曲线点加/倍乘/标量乘
  _encoding.py     点与标量压缩编码（严格/最短/域外检查）
  _schnorr.py      Schnorr 风格教学签名与严格验签
  _batch.py        教学批验签（聚合 + exact 逐项，共享倍点表）
tests/
  reference.py                     独立参考（不依赖被测核心）
  test_group_law.py                穷举群表/结合律/单位元/逆点
  test_encoding.py                 编码严格性
  test_schnorr.py                  验签/篡改/可塑性/无穷与离曲线
  test_batch.py                    批验签/抵消反例/严格拒绝/加法计数
  test_reference_independence.py   参考隔离性（AST）
demo.py          固定输入演示
README.md
requirements.txt （仅说明：标准库，无第三方依赖）
```
