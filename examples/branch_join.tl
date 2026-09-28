# 分支汇合：任一分支带入污点，汇合后都必须保守追踪。
def main() {
    x = read_input();
    if (1 == 1) {
        y = x;
    } else {
        y = "constant";
    }
    exec(y);
}
