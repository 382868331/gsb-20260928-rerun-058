# 未知语义：外部调用（无论无参/带参）可能净化、忽略或改变数据，
# 其返回值不能当成干净数据，也不能把“实参污点穿过未知函数”当成已证实路径。
# 缺少行为说明时：流入 sink 给 TAINT-UNCERTAIN（依据 unknown），整体 INCOMPLETE。
# 若提供 returns="clean" 说明则 SAFE；returns="tainted" 则 TAINT-ASSUMED、
# 结论 ASSUMED_UNSAFE，且诊断记录它依赖哪条说明。

def main() {
    token = get_token();
    exec(token);
}
