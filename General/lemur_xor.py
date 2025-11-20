from PIL import Image
from pwn import xor


with Image.open(r"C:\Users\panos\Desktop\flag.png") as img:
    size = img.size
    flag = img.tobytes()
with Image.open(r"C:\Users\panos\Desktop\lemur.png") as img:
    lemur = img.tobytes()

flag_xor_lemur = xor(flag, lemur)
(Image.frombytes('RGB', data = flag_xor_lemur, size = size)).save(r"C:\Users\panos\Desktop\result.png")
