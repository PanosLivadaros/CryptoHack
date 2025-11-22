alph = ["", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
temp = ""
for i in range(1, 27):
    for j in "GENQRTEBPRELORSBERQRYNL":
        temp += alph[((alph.index(j) - i) % 26)]
    print(temp)
    temp = ""

