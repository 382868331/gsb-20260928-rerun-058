# 未知外部调用：没有行为说明时，返回值不是干净数据。
# fetch_remote() 语义不明，分析无法完成，结论只能是 INCOMPLETE，
# 绝不能因为“没有确认的污点”就报 SAFE。
def main() {
    x = fetch_remote();
    exec(x);
}
