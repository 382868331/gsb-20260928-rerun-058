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
  分析器**不臆测**其语义：
  - 实参已带污点时，保守按“数据可能原样流出”追踪（已证实证据链，
    `TAINT-FLOW`）；
  - 无实参或实参本身无法判定时，返回值是语义未知的“潜在不可信值”，
    携带 `unknown` 路径跳；它流入 sink 产生 `TAINT-UNCERTAIN` 警告，
    程序中只要出现这种无说明调用，结论只能是 `INCOMPLETE`，
    **绝不输出无依据的 `SAFE`，也不把未知调用直接报成已发生的漏洞**。
- **受限行为说明**：可通过 `AnalysisConfig(external_specs=...)` 为部分外部
  调用提供说明 `ExternalSpec(name, description, returns)`，`returns` 取：
  `"clean"`（返回值干净）/ `"tainted"`（视为不可信来源）/
  `"propagate"`（污点随实参传播，默认）。分析结果的 notes 会记录结论依赖了
  哪些说明——说明变化，结论可能随之变化。

已证实风险与无法判定的路径**分开诊断**：`TAINT-FLOW`（error）与
`TAINT-UNCERTAIN`（warning）互不吞没；只要存在未完成判断，结论为
`INCOMPLETE`（即使同时存在已证实风险路径，该路径仍完整呈现）。

结论取值：`UNSAFE`（污点到达 sink）/ `INCOMPLETE`（分析未完成）/
`SAFE`（完整分析且无污点流）/ `PARSE_ERROR`。

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
