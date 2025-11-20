flag = ""
for i in "label":
    flag += chr(ord(i) ^ 13)
print(flag)
