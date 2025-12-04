import time
from telnetlib import Telnet 
import json
from statistics import median, mean
from tqdm import trange


def two_clursturing(datas, epoch=10):
    centor=[min(datas),max(datas)]
    label=[0]*len(datas)
    for _ in range(epoch):
        bag=[[],[]]
        for i in range(len(datas)):
            if abs(datas[i]-centor[0])<abs(datas[i]-centor[1]):
                label[i]=0
                bag[0].append(datas[i])
            else:    
                label[i]=1
                bag[1].append(datas[i])
        centor[0]=mean(bag[0])
        centor[1]=mean(bag[1])
        centor.sort()
    return label


cli=Telnet("socket.cryptohack.org",13398)

print(cli.read_until(b"\n"))

precision=10

found=b""
pbar = trange(0*8,43*8,8)
for i in pbar:
    val=0
    ssamp=[]
    for j in trange(8,leave=False):
        sample=[]
        query={"option":"get_bit","i":i+j}
        eq=json.dumps(query).encode()
        for _ in range(precision):
            st=time.time_ns()
            cli.write(eq)
            cli.read_until(b"\n")
            ed=time.time_ns()
            sample.append(ed-st)
        ssamp.append(median(sample))

    b="".join(map(str,two_clursturing(list(reversed(ssamp)))))
    found+=bytes([int(b,2)])
    pbar.set_description(str(found))
    
print(found)
