

if __name__ == "__main__":
    system_equations=[(2,5),(3,11),(5,17)]
    solution1 = ChineseRemainder(system_equations)
    solution2 = ChineseRemainder(system_equations, fast=True)
    assert solution1==(872,935)
    assert solution2==(872,935)