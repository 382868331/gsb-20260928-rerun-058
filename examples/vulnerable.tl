# 反例：不可信输入经跨函数传递流入危险操作。
def wrap(cmd) {
    return cmd;
}

def main() {
    x = read_input();
    y = wrap(x);
    exec(y);
}
