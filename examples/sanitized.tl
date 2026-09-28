# 正例：经过明确净化后，污点不能与原值混为一份。
def clean(v) {
    return sanitize(v);
}

def main() {
    x = read_input();
    y = clean(x);
    exec(y);          # y 已净化：安全
    exec(x);          # 原变量 x 仍带污点：应报警
}
