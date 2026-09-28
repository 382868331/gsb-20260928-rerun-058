# 递归：分析设上限，未分析完不能说安全。
def looper(n) {
    if (n == 0) {
        return n;
    } else {
        return looper(n - 1);
    }
}

def main() {
    v = looper(read_input());
    exec(v);
}
