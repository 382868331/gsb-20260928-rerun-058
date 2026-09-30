# 未知语义：无参数外部调用的返回值不能当成干净数据。
# 缺少行为说明时：流入 sink 给 TAINT-UNCERTAIN，整体 INCOMPLETE。
# 若调用方为 get_token 提供 returns="clean" 的说明，则结论才可能是 SAFE，
# 且分析结果会记录该结论依赖此说明。

def main() {
    token = get_token();
    exec(token);
}
