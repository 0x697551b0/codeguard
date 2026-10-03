# CodeGuard 内置静态规则手册

规则引擎基于 Python 标准库 `ast`，零第三方依赖。所有规则都在
`codeguard/static_analysis.py` 中实现，可用 `python -m codeguard rules` 查看。

**设计原则：宁缺毋滥。** 每条规则都尽量只匹配"确定有问题"的语法形态，
对存在安全写法的场景主动排除。测试套件中约一半用例是**负例（误报回归）**。

## 编号约定

| 编号段 | 类别 | 关注点 |
| --- | --- | --- |
| `CG1xx` | 安全 security | 可被利用的漏洞 |
| `CG2xx` | 可靠性 reliability | 会崩、会静默失败、会泄漏 |
| `CG3xx` | 可维护性 maintainability | 难改、难测、难读 |
| `CG4xx` | 风格 style | 规范与一致性 |
| `CG000` | 元信息 meta | 结果被截断等提示 |

---

## 安全（CG1xx）

### CG101 · 危险的动态执行调用 · CRITICAL

**检测**：调用 `eval` / `exec` / `compile` / `__import__`。

**风险**：输入不可信时等价于任意代码执行（RCE）。

```python
# ❌ 命中
def evaluate_filter(expression):
    return eval(expression)
```

**修复**：改用 `ast.literal_eval`、`json.loads` 或显式解析器。

---

### CG102 · Shell 注入风险 · CRITICAL / HIGH / MEDIUM

**检测**：
- `os.system` / `os.popen` —— CRITICAL
- `subprocess.*` 传 `shell=True` —— CRITICAL
- 命令参数由 f-string / `%` / `.format()` / `+` 拼接 —— HIGH
- 命令来自变量、无法静态判定 —— MEDIUM（需人工确认）

**主动排除**：`subprocess.run(['ls', '-l'], check=True)` 这类**列表参数 + 无插值**
的写法不会命中。

```python
# ❌ CRITICAL
os.system("bash /opt/backup/%s.sh" % script_name)
subprocess.call("rm -rf %s/*" % path, shell=True)

# ✅ 安全，不命中
subprocess.run(["ls", "-l"], check=True)
```

---

### CG103 · 不安全的反序列化 · CRITICAL / HIGH

**检测**：`pickle.load(s)`、`marshal.loads`（CRITICAL）、`yaml.load`（HIGH）。

**修复**：改用 JSON / MessagePack 等安全格式；YAML 用 `yaml.safe_load`。

---

### CG104 · 关闭 TLS 校验 · HIGH

**检测**：调用中出现 `verify=False` / `ssl_verify=False` / `check_hostname=False`。

**修复**：移除该参数；自签证书场景通过 `verify="/path/ca.pem"` 指定 CA。

---

### CG105 · 硬编码密钥 · CRITICAL / HIGH

**检测**：变量名含 `password` / `secret` / `token` / `api_key` / `credential` / `auth`
等关键字，且赋值为字符串字面量。

**主动排除**：变量名或值含 `placeholder` / `example` / `dummy` / `your_` / `xxx` 等
占位提示词时不报（如 `password = "your_password_here"`）。

**证据脱敏**：报告中只显示 `sk-l********`，**不写入密钥原文**。
值为 `sk-` / `ghp_` / `AKIA` / `-----BEGIN` 开头时判为 CRITICAL。

```python
# ❌ CRITICAL
API_TOKEN = "sk-live-9f8a7b6c5d4e3f2a1b0c"

# ✅ 不命中（占位符）
password = "your_password_here"
```

**修复**：改为 `os.environ["SERVICE_TOKEN"]`，并**轮换已泄露的凭据**。

---

### CG106 · SQL 注入风险 · HIGH / MEDIUM

**检测**三种写法：

1. **内联插值**：`cursor.execute(f"... WHERE id = {uid}")`
2. **变量间接传参**（真实代码里最常见，只看参数表达式会整个漏掉）：
   ```python
   sql = "SELECT id FROM users WHERE email = '%s'" % email
   cursor.execute(sql)          # ← 命中，并指向第 1 行的定义处
   ```
3. **字面量占位符未参数化**：`execute("... WHERE id = %s")` 只传了 1 个参数

**主动排除**：传了额外参数说明走的是驱动占位符参数化，**不报**。
字面量 SQL 存变量后执行且未传参，记为 MEDIUM（需人工确认）。

```python
# ✅ 安全，不命中
sql = "SELECT id FROM t WHERE email = %s"
cursor.execute(sql, (email,))
```

**修复**：SQL 写成固定模板，参数经驱动占位符传入。

---

### CG107 · 弱随机数用于安全场景 · MEDIUM

**检测**：`random.random/randint/randrange/choice/shuffle` 所在行同时出现
`token` / `password` / `secret` / `salt` / `session` / `nonce` / `key` 等词。

**修复**：改用 `secrets.token_urlsafe(32)` / `secrets.token_hex(16)`。

---

### CG108 · 临时文件竞态 · HIGH

**检测**：`tempfile.mktemp`（存在 TOCTOU 竞态）。

**修复**：改用 `tempfile.mkstemp()` 或 `NamedTemporaryFile`。

---

## 可靠性（CG2xx）

### CG201 · 裸 except · HIGH

**检测**：`except:` 不带任何异常类型。

**风险**：连 `KeyboardInterrupt`、`SystemExit` 一起吞掉，程序无法中断、错误被掩盖。

**修复**：捕获具体异常类型，或至少 `except Exception:` 并记录日志后重新抛出。

---

### CG202 · 捕获过于宽泛的异常 · MEDIUM

**检测**：`except Exception:` / `except BaseException:`，且函数体中**既无日志记录
也无 `raise`**。

**修复**：`logger.exception(...)` 后重新抛出，或收窄捕获类型并给出降级逻辑。

---

### CG203 · 可变默认参数 · HIGH

**检测**：默认参数为字面量 `[]` / `{}` / `set()`。

**风险**：默认值在函数定义时求值一次并被所有调用共享，就地修改会污染后续调用。

```python
# ❌ 命中
def load_users(db_path, include_deleted=[], verbose=True): ...

# ✅ 修复
def load_users(db_path, include_deleted=None, verbose=True):
    include_deleted = [] if include_deleted is None else include_deleted
```

---

### CG204 · 直接比较 None/True/False · LOW

**检测**：`x == None`、`x != None`、`x == True` 等。

**修复**：改用 `is` / `is not`。

---

### CG205 · 除法未做零值保护 · CRITICAL

**检测**：除数为**字面量 0**（`a / 0`、`a // 0`、`a % 0`）—— 必然抛
`ZeroDivisionError`，属确定性缺陷。

---

### CG206 · 资源未使用 with 管理 · MEDIUM

**检测**：`open()` 调用不在 `with` 语句上下文中。

**风险**：异常路径下文件句柄不会及时释放。

**修复**：`with open(path, encoding="utf-8") as fh: ...`

---

### CG207 · assert 用于运行时校验 · MEDIUM

**检测**：`assert` 的表达式里出现 `input` / `request` / `args` / `json` / `param` /
`user` 等外部输入特征词。

**风险**：`python -O` 会移除所有 assert，校验随之失效。

**修复**：改为显式判断并抛出 `ValueError` 或自定义异常。

---

### CG208 · finally 中使用 return/break/continue · MEDIUM

**检测**：`try/finally` 的 `finally` 块中出现跳转语句。

**风险**：会覆盖正在传播的异常，调用方拿到错误的正常返回值。

```python
# ❌ 命中
def cleanup_workspace(path):
    try:
        subprocess.call(...)
    finally:
        return True          # 异常被静默吞掉
```

---

## 可维护性（CG3xx）

### CG301 · 函数过长 · MEDIUM

**检测**：函数体超过 **50 行**。

**修复**：按单一职责拆分，并补充单元测试。

---

### CG302 · 嵌套过深 · MEDIUM

**检测**：`if/for/while/with/try/match` 的最大嵌套深度超过 **4** 层。

**修复**：使用卫语句（early return）或提取内层逻辑为独立函数。

---

### CG303 · 函数参数过多 · LOW

**检测**：位置参数 + 仅关键字参数总数超过 **6** 个。

**修复**：用 `@dataclass` 聚合参数，或采用"配置对象 + 关键字参数"模式。

---

### CG304 · 缺少文档字符串 · LOW

**检测**：公共（不以 `_` 开头）函数缺少 docstring。`__init__` 记为 INFO。

---

### CG305 · 重复的字面量 · LOW

**检测**：同一字符串/数字字面量出现 **3 次以上**（长度 ≥ 4，排除常见魔法值）。

**修复**：提取为模块级常量或放入配置。

---

### CG307 · 类型注解缺失 · INFO

**检测**：公共函数缺少返回值注解。

**修复**：补充 `-> ReturnType`，必要时用 `typing.Optional` 或 `|` 联合类型。

---

## 风格（CG4xx）

### CG401 · 行长度超限 · INFO

**检测**：单行超过 **120** 字符。单文件最多报 3 处，避免刷屏。

---

### CG402 · 行尾空白 · INFO

**检测**：行尾存在多余空白。单文件最多报 5 处。

**修复**：配置编辑器 trim trailing whitespace，或运行 `ruff format` / `black`。

---

### CG403 · 未使用的导入 · LOW

**检测**：导入的名称在文件中未被引用。

**主动排除**：
- `from __future__ import ...`（编译指示，没有可引用的名称）
- `import *`（无法判断）
- 下划线开头的名称
- 出现在字符串中的名称（覆盖字符串注解与 `__all__`）

---

### CG404 · 变量遮蔽内置名称 · LOW

**检测**：以 `list` / `dict` / `str` / `id` / `type` 等内置名作为变量名。

**修复**：改用语义化名称，如 `items` / `mapping` / `user_id`。

---

### CG405 · 语法错误 · CRITICAL

**检测**：文件无法被解析为合法 Python 语法。

**说明**：命中后该文件的其他规则**全部跳过**（语义分析不可靠）。
这是一条重要的"前置"规则 —— 示例代码若含语法错误，会导致整个文件的分析结果消失。

---

## CG000 · 条目过多，已截断 · INFO

**说明**：单文件命中超过上限（默认 200 条）时，只保留最严重的部分并追加此提示。

---

## 扩展新规则

1. 在 `RULES` 元组中登记规则（编号、标题、类别、默认级别、说明）；
2. 在 `_FindingCollector` 中添加对应的 `visit_*` 处理或在跨语句检查里实现；
3. 用 `self.add(rule, title=..., line=..., evidence=..., explanation=..., suggestion=...)` 记录；
4. **必须**在 `tests/test_static_analysis.py` 中同时补充**正例与负例**测试。

```python
# 示例：新增一条规则
Rule("CG109", "使用 md5 哈希口令", "security", Severity.HIGH,
     "MD5 已被证明不安全，口令应使用 bcrypt/argon2。")
```

负例测试尤其重要：只验证"能发现问题"而不验证"不误报"，
规则数量增长后会迅速变得不可用。
