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
  - 可通过 `ExternalSpecScope.file()` 或
    `ExternalSpecScope.call_site(line, col)` 把同一库的说明限定到文件或单个调用点。
    `external_specs` 接受多个同库说明；窄作用域在实际匹配位置覆盖全局说明，
    未覆盖到的调用仍按未知外部调用处理，不会继承邻近调用的净化结论。局部假设
    ID 形如 `lib@v2[call::1:47]`，输出、冲突、撤回、快照重载和命名情景投影都
    同时保留版本与适用范围；联合情景只在实际相交的同一个调用实例检查互斥。
- **按结论解释最小必要假设**：`AnalysisResult.explanations` 为每个 sink 位置
  （稳定 ID：`函数名:行:列`）汇总替代路径。风险路径的假设以“最小替代假设组”
  表示：`(A) 或 (B)` 中 A、B 都不是不可或缺；只有所有替代路径共同需要、且
  删除后该路径无法成立的假设才进入 `indispensable_assumptions`。安全常量、
  语言内净化路径以 `kind="safe"` 独立保存；与未知/风险分支合流时不会相互吞没。
- **相互矛盾的行为假设**：`AnalysisConfig(spec_alternatives=...)` 可登记同一
  外部函数的额外候选说明（如不同版本）。两条候选对**同一次调用**给出互斥
  结果（干净值 vs 不可信值）时记为 `AssumptionConflict`：冲突 ID 含函数名与
  调用位置，`constraints` 列出每条假设在该次调用上的互斥约束。冲突按调用
  实例判定——同一假设作用于不同调用实例不算自相矛盾；多处独立冲突各自
  独立，撤回一项假设只解除涉及它的冲突，其余冲突保留。
- **情景化解释**：`AnalysisResult.scenarios` 把每个结论位置上的依据组织成
  需要共同成立的情景：`risk`（存在可行风险）/ `contradictory`（假设组内部
  互斥、无法共同成立）/ `no_risk`（当前依据下未发现风险）/ `undecidable`
  （含未知返回值或递归截断，无法判断）。`ConclusionExplanation` 进一步区分：
  `compatible_groups`（彼此相容、可共同采用的替代依据）、
  `scenario_only_groups`（互相冲突、只能分情景讨论的依据）与
  `infeasible_assumption_groups`（含互斥假设、拼不成可行路径的依据）。
  若所有风险路径都依赖互斥假设，结论是 `INCOMPLETE` 而非 `SAFE`——
  矛盾前提推不出空洞的安全结论；未知返回值与递归截断也不会被补出默认
  结果来消除不确定性。
- **临时关闭假设**：`AnalysisConfig(disabled_assumptions={"lib@v1"})` 可临时
  撤回一项或一组说明；关闭后相关路径回到未知外部调用语义，可比较已证实风险、
  条件风险、无法判断和独立安全路径的变化。撤回冲突中的一方后，被冲突
  锁死的路径重新可能。
- **研究快照与增量修订**：`snapshot_analysis(source, config)` 保存源码、说明、
  说明版本、候选假设、冲突、情景、结论位置和解释；`ResearchSnapshot.save()/load()`
  可持久化为 JSON。`revise_specs(snapshot, new_specs, disabled_assumptions=...,
  spec_alternatives=...)` 重算后按稳定 sink 位置输出 `affected_conclusions` 与
  `reused_conclusions`，未受说明变更影响的解释沿用旧对象；`RevisionReport` 另
  给出 `resolved_conflicts` / `new_conflicts` / `remaining_conflicts`，并把结论
  变化归因为 `conflict_driven_conclusions`（冲突解除）与
  `path_driven_conclusions`（程序路径变化）。旧快照中的冲突、情景与结论可
  单独回看，与修订后的结果对照。
- **有名称的联合情景比较研究**：`study_scenarios(source, scenarios, config)`
  把若干说明版本显式组成有名称、需共同成立的联合情景
  （`NamedScenario(name, description, assumptions=("relay@v1", ...))`），
  研究者据此比较各情景下的安全结论，而不是逐条查看互不相容的备选。所有
  情景共享同一份基础外部返回分析（`ScenarioStudy.base_result`），再按情景对
  逐路径依据做投影：只有路径所需说明全部被该情景包含时依据才成立。
  - 风险注明情景与版本：风险依据写入 `PathExplanation.scenario` 与其
    `assumptions`（名称@版本）；`ScenarioSinkConclusion` 给出每个 sink 在该
    情景下的 `confirmed_risk` / `conditional_risk` / `no_risk`，某情景下的
    无风险结论不会扩展到其它备选。
  - 最小冲突依据：不可行情景的 `minimal_conflicts` 逐个列出组内独立的
    互斥冲突（作用于同一次调用实例的两条说明）。一个情景可含多组独立
    矛盾；用 `disabled_assumptions` 局部撤销一条说明只解除涉及它的冲突，
    其余冲突保留，其它可行情景不受影响（`NamedScenarioResult.feasible`）。
  - 未知外部返回不等于无可行情景：情景内仍含无说明的外部返回时该 sink
    为 `undecidable`、情景总判 `INCOMPLETE`；所有情景都不可行时研究总判
    也是 `INCOMPLETE`，但二者来自 `ScenarioSinkConclusion.state` 与
    `ScenarioStudy.verdict` 两个不同层级，都不会被归成安全。
  - 派生比较研究、旧查询保持原依据：`revise_study(study, new_specs,
    scenarios=..., disabled_assumptions=..., spec_alternatives=...)` 基于
    `revise_specs` 派生新研究并重投影，旧 `ScenarioStudy` 对象不被修改；
    `ScenarioStudy.save()/load()` 可把研究（含情景、最小冲突、逐路径依据）
    持久化为 JSON；`format_study_text(study)` 输出可比较的文本结论。

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
