# TaintLab 代码安全分析平台（分析基础）

首个功能：在一门小型教学语言 **TaintLab** 中静态追踪“不可信输入”如何流到
“危险操作”。项目只把源程序当**文本**分析，不执行任何被分析程序。

## 语言概览

```
def 函数名(参数, ...) { 语句; ... }
语句: x = 表达式; | return 表达式; | 函数调用; | if (条件) { } else { }
```

内置建模函数（语言层面的固定语义，不执行被分析代码）：

| 类别 | 函数 | 含义 |
| --- | --- | --- |
| source（不可信来源） | `read_input()` | 产生污点值 |
| sanitizer（净化） | `sanitize(v)` | 返回干净值；原值仍带污点，二者不合并 |
| sink（危险操作） | `exec`、`eval_sql` | 污点到达即报警 |

## 分析能力

- **跨函数传参**：调用点把实参污点绑定到形参，`return` 把污点带回调用点；
  每条污点事实自带可回到源文行列号的完整传播路径
  （`source -> assign -> call_in -> call_out -> join -> sink`）。
- **分支汇合**：分别分析两个分支，汇合时对变量污点取并集（任一分支可能
  赋值即保留污点），并在路径中记录 `join` 一跳。
- **净化分离**：`sanitize()` 的结果不携带原污点；把净化值赋给新变量后，
  新变量干净、原变量仍受污染，不会混成一份。
- **递归与深度上限**：沿调用栈检测递归，`AnalysisConfig.max_call_depth`
  （默认 32）限制展开深度；触顶的调用按“潜在不可信”处理并产生
  `TAINT-UNCERTAIN` 警告，整体结论为 `INCOMPLETE` —— 未分析完绝不报 `SAFE`。
- **未知外部调用**：程序中调用了既非内置、又未在程序内定义的函数时，
  分析器不假设它会净化、忽略或原样返回实参。无论是否有参数，其返回值都
  是语义未知的“潜在不可信值”，携带 `unknown` 路径跳；流入 sink 时只产生
  `TAINT-UNCERTAIN`（无法判断），整体为 `INCOMPLETE`。这不是已证实漏洞；
  未经过该返回值的常量 sink 仍保持无诊断，不会被株连报警。
- **受限行为说明**：可通过 `AnalysisConfig(external_specs=...)` 为部分外部
  调用提供说明 `ExternalSpec(name, description, returns, version=...)`，
  `returns` 取：
  `"clean"`（返回值干净）/ `"tainted"`（视为不可信来源）/
  `"propagate"`（污点随实参传播，默认）。`AnalysisResult.assumptions` 给出
  假设 ID、版本、使用位置和调用链；notes 中也会记录本次使用的说明。依赖
  说明的 sink 诊断为 `TAINT-ASSUMED`，由说明推出的安全结论总判为 `ASSUMED`。
  `compare_external_specs(old, new)` 可比较两版说明；某条说明被撤回时，只有
  使用对应假设 ID 的诊断或结论失效，其他结论不受影响。

三类证据分开诊断：`TAINT-FLOW` / `CONFIRMED`（已证实）、
`TAINT-ASSUMED` / `ASSUMED`（依赖外部说明）、`TAINT-UNCERTAIN` /
`UNKNOWN`（无法判断）。证据链互不吞没；同时存在已证实和无法判断路径时，
两条路径都会呈现，总判为 `INCOMPLETE`。

结论取值：`UNSAFE`（存在已证实风险）/ `ASSUMED`（结论依赖外部说明）/
`INCOMPLETE`（存在无法判断项）/ `SAFE`（完整分析、无风险且不依赖外部说明）/
`PARSE_ERROR`。

## 使用

```bash
python -m taintlab examples/vulnerable.tl   # 反例：UNSAFE
python -m taintlab examples/sanitized.tl    # 净化值安全、原值报警
python -m taintlab examples/branch_join.tl  # 分支汇合
python -m taintlab examples/recursion.tl    # INCOMPLETE
python -m taintlab examples/external_call.tl  # 未知外部调用：INCOMPLETE
python -m unittest discover -s tests        # 自带正反例测试
```

## 代码结构

- `taintlab/lexer.py`、`taintlab/parser.py`、`taintlab/ast_nodes.py`：词法/语法/AST
- `taintlab/callgraph.py`：函数调用关系
- `taintlab/model.py`：诊断记录、传播路径、分析结论
- `taintlab/analyzer.py`：污点传播分析器
- `examples/`、`tests/`：正反例与回归测试
