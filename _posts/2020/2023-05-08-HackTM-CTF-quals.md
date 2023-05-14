---
title : HackTM CTF 2020 - Quals
categories : ['2020', 'HackTM CTF']
---

## Reversing

### baby bear (442pts)

#### Description

```
Goldilocks is in big trouble: baby bear isn't going to let her run this time. She needs a bear negotiator, quick!
```

`original.baby_bear`가 주어진다.

```shell
$ file original.baby_bear 
original.baby_bear: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

```
$  ./original.baby_bear 

  (c).-.(c)    █  █         █         █
   / ._. \     █  █         █         █
 __\( Y )/__   █  ███   ███ ███  █  █ ███   ███   ███ █ ██
(_.-/'-'\-._)  █  █  █ █  █ █  █  ██  █  █ █████ █  █ ██
   || X ||     █  █  █ █  █ █  █  █   █  █ █     █  █ █
 _.' `-' '._   █  ███   ███ ███  █    ███   ███   ███ █
(.-./`-'\.-.)  █
 `-'     `-'   █  Baby bear says: 0001110101000000101001111001101100000001000101

What do you say? asdf
1110111000101010001101111010101010101010101010
Baby bear is thinking...

"Someone's been eating my porridge and they ate it all up!" cried the Baby bear.
```

바이너리를 실행해보면 2진수를 출력해주고 입력을 받는다.

ida로 열어보면 upx로 패킹되어 있는 것 같지만 upx unpack이 불가능하다..

일단 보이는대로 분석해보자

#### start

```c++
__int64 start() {
  signed __int64 fp; // rax
  unsigned int v1; // edi
  signed __int64 v2; // rax
  signed __int64 v3; // rax
  __int64 res; // rdx
  char * ptr; // rsi
  _BYTE * buf16; // rdi
  char val; // al
  __int64 i; // rcx
  signed __int64 v9; // rax

  fp = sys_open("/dev/urandom", 0, 0);
  v1 = fp;
  v2 = sys_read(fp, buf, 0x10 uLL);
  v3 = sys_close(v1);
  ptr = buf;
  buf16 = buf + 16;
  do {
    val = * ptr++;
    i = 8 LL;
    LOBYTE(res) = val;
    do {
      * buf16++ = res & 1;
      LOBYTE(res) = (unsigned __int8) res >> 1;
      --i;
    }
    while (i);
  }
  while (ptr != & buf[16]);
  if (!byte_600800) {
    buf16 = 0 LL;
    v9 = sys_write(0, (const char * ) & loc_40012B, 0x21A uLL);
  }
  byte_600862 = 46;
  return sub_40035C(buf16, 0x600780 LL, res);
}
```

`buf[16:8*16]`에 0x10바이트 랜덤한 값의 각 비트를 저장하고 `sub_40035C` 를 호출한다.

```
loc_400528:
mov     ds:byte_600862, 2Eh ; '.'
mov     rsi, 600780h
jmp     sub_40035C
start endp
```

다른 함수들이 디컴파일 결과가 보기 힘들어서 flag가 출력되는 부분을 먼저 찾아봤다.

`sub_4000B0` 함수 안에 flag를 출력하는 부분을 찾을 수 있었다.

```c++
...
if (!memcmp(byte_600832, & unk_600801, 0x2E uLL)) {
  v8 = sys_write(0, aYeahThatSounds, 0x51 uLL);
  v9 = sys_open("flag", 0, 0);
  v10 = v9;
  v11 = sys_read(v9, buf, 0x100 uLL);
  v12 = sys_close(v10);
  v14 = sys_write(0, buf, v13);
}
...
```

어떤 값들이 비교되는 건지 확인하기 위해 `memcmp` 부분(0x400617)에 breakpoint를 걸고 값을 확인해봤다.

첫번째 입력 : `1111`

```
pwndbg> x/6gx 0x600801
0x600801:       0x0101000000000000      0x0000010000000000
0x600811:       0x0000010001000001      0x0100000000000101
0x600821:       0x0000010001010001      0x0000010100000100
pwndbg> x/6gx 0x600832
0x600832:       0x0101000100010101      0x0101010101010101
0x600842:       0x0101010100010101      0x0100010001000100
0x600852:       0x0100010001000100      0x0000010001000100
```

두번째 입력 : `1111`

```
pwndbg> x/6gx 0x600801
0x600801:       0x0000000001000101      0x0000000000000001
0x600811:       0x0001000001000000      0x0000000101000001
0x600821:       0x0100010101010001      0x0000000000010000
pwndbg> x/6gx 0x600832
0x600832:       0x0101000100010101      0x0101010101010101
0x600842:       0x0101010100010101      0x0100010001000100
0x600852:       0x0100010001000100      0x0000010001000100
```

세번째 입력 : `2222`

```
pwndbg> x/6gx 0x600801
0x600801:       0x0001010100000001      0x0000000100000100
0x600811:       0x0001010001010000      0x0101000100000101
0x600821:       0x0100000100000100      0x0000010001010001
pwndbg> x/6gx 0x600832
0x600832:       0x0000000100010000      0x0101000000010100
0x600842:       0x0101000101000000      0x0100010001000101
0x600852:       0x0100010001000100      0x0000010001000100
```

`0x600801`은 `/dev/urandom`의 영향을 받아 같은 입력을 줘도 바뀐다.

`0x600832`가 내 입력에 대한 값임을 알 수 있다.

입력으로 계산한 값이 처음 출력되는 2진수가 되도록 하면 플래그를 얻을 수 있다.

#### sub_4000B0

`byte_600832`을 참조하여 값을 바꾸는 곳이 `sub_4000B0` 함수밖에 없다.

디컴파일된 결과는 읽기가 힘들어 어셈블리어로 봤다.

```
// var_8 = byte ptr - 8

mov     r9, rsi
mov     r10, rdi
mov     rdi, offset byte_600832
movzx   r8, ds:byte_600831
add     rdi, r8
stosb   // byte_600832[byte_600831] = al

loc_4000CD:
inc     ds:byte_600831      // byte_600831++
mov     rdi, r10
add     al, 30h ; '0'
push    0
mov     [rsp+8+var_8], al   // [rsp] = al
xor     rdi, rdi
mov     rsi, rsp            // rsi = rsp

loc_4000E4:
add     rsp, 8
xor     ah, ah
div     al                  // 무조건 1

loc_4000EC:
mov     edx, 1
syscall                 ; LINUX - // sys_write
dec     ds:byte_600862      // byte_600862--
jz      loc_40053F
// start 함수에서 byte_600862를 0x2e로 초기화했으니 0x2e번 돌 것 같음
...

loc_40053F:
mov     al, ds:byte_600831
cmp     al, ds:byte_600800
jz      loc_4005E2
mov     ecx, 2Fh ; '/'
mov     rsi, offset byte_600831
mov     rdi, offset byte_600800
rep movsb                   // memcpy(0x600800, 0x600831, 0x2F)
mov     ecx, 2Fh ; '/'
xor     al, al
mov     rdi, offset byte_600831
rep stosb                   // memset(0x600831, 0, 0x2F)
mov     edx, 13h        ; count
mov     rsi, offset aWhatDoYouSay ; "\n\nWhat do you say? "
xor     rdi, rdi        ; fd
mov     eax, 1
syscall                 ; LINUX - sys_write
jmp     short loc_4005AF

loc_4005AF:
mov     rdi, offset buf
mov     al, 0
mov     ecx, 10h
rep stosb
mov     edx, 10h        ; count
mov     rsi, offset buf ; buf
mov     edi, 1          ; fd
mov     eax, 0
syscall                 ; LINUX - sys_read // read(0, buf, 0x10)
jmp     loc_4004D7 // start 부분으로 jump
...
loc_4005E2:             ; count
mov     edx, 1Ah
mov     rsi, offset aBabyBearIsThin ; "\nBaby bear is thinking...\n"
xor     rdi, rdi        ; fd
mov     eax, 1
syscall                 ; LINUX - sys_write
jmp     short loc_400617
...
```

위 부분만 간단하게 정리하면 아래와 같다.

```python
byte_600832[byte_600831] = al
byte_600831 += 1
print(chr(30 + al))
byte_600862 -= 1
if byte_600862 == 0:
    memcpy(0x600800, 0x600831, 0x2F)
    memset(0x600831, 0, 0x2F)
    input("What do you say?")
    #### start 중간으로 jump ####
else:
    print("Baby bear is thinking...")
    ...
```

저장되는 2진수는 `sub_4000B0`이 호출되기 전에 설정된 `al`임을 알 수 있다.

`al`이 어떻게 계산되는 값인지 알아내야 한다.

#### sub_40035C

`sub_40035C`는 처음에 `start`에서
```
mov     rsi, 600780h
jmp     sub_40035C
```
로 실행된다.

```
mov     rsp, offset unk_601063
lodsb   // mov al, [esi]; add esi, 1;
cmp     al, 1
jnz     short loc_4003CD
...
```

`esi`가 가리키는 곳에 있는 값에 따라 다르게 분기된다.

어셈블리어를 분석해보면 다음과 같이 동작한다.

```python
al = *(char *)esi
esi += 1
if al == 1: # 0x400346
    jump 0x400346
else: # 0x4003CD
    print(0)
    al = *(char *)esi
    esi += 1
    if al == 0: # 0x4003E1
        al = *(char *)esi
        esi += 1
        if al == 0: # 0x400461
            print(0)
            al = *(char *)esi
            esi += 1
            if a1 == 0: # 0x400442
                al = *(char *)esi
                esi += 1
                if al == 0: # 0x400451
                    jump 0x4003C7
                else:
                    jump 0x4003B3
            else: # 0x400478
                print(1)
                al = *(char *)esi
                esi += 1
                if al == 1: # 0x4003B3
                    print(1)
                    al = *(char *)esi
                    esi += 1
                    if al == 0: # 0x40035C
                        jump 0x40035C
                    else: # 0x4003C7 (0x400104)
                        al = *(char *)esi
                        esi += 1
                        print(1)
                        if al == 1: # 0x40035C
                            jump 0x40035C
                        else: # 0x40011B
                            al = *(char *)esi
                            esi += 1
                            if al+1 == 1: # 0x400461
                                jump 0x400461
                            else: # 0x400126
                                call 0x40035C
                else: # 0x400442
                    jump 0x400442
        else: # 0x40037E
            jump 0x40037E

    else: # 0x400370
        print(0)
        al = *(char *)esi
        esi += 1
        if al == 0: # 0x40037E
            jump 0x40037E
        else: # 0x4003F3
            jump 0x4003F3
```

#### sub_400346
```
mov     al, 1
call    sub_4000B0      // 1 출력
lodsb
dec     al
jz      loc_400457

js      loc_4003F3
sub_400346 endp

loc_4003F3:             // al - 1 < 0 이면
mov     al, byte ptr ds:loc_40012B+1 // al = 0x20
mov     rdi, offset byte_400325
movsx   rax, al
add     rdi, rax        // rdi = 0x400325 + 0x20
cmpsb                   // rsi, rdi 비교 (0인지 비교, rsi++, rdi++)
mov     al, 0
mov     dl, 1
cmovnz  rax, rdx        // 같으면 0, 다르면 1
push    rax
or      al, 1
call    sub_4000B0      // 1 출력
pop     rax

loc_40041D:
mov     rbx, offset loc_4003ED
xor     rbx, 4003A3h
cmp     al, 1
mov     edx, 0
cmovz   rbx, rdx        // al == 1이면 4003A3, 아니면 4003ED로 점프
xor     rbx, 4003A3h
jmp     rbx

loc_400457:
lodsb
mov     qword ptr [rsp+0], offset loc_40041D
retn                    // jump 40041D
```

```python
print(1)
al = *(char *)esi
esi += 1
if al == 1: # 0x400457
    al = *(char *)esi
    esi += 1
    if al == 1:
        jump 0x4003A3
    else:
        jump 0x40037E
else: # 0x4003F3
    print(1)
    al = *(char *)esi
    esi += 1
    if al == 0:
        jump 0x40037E
    else:
        jump 0x4003A3
```

#### sub_40037E

```
lodsb
push    offset sub_400394
push    offset loc_400478
shl     al, 3
movzx   rax, al
add     rsp, rax
retn
```

```python
al = *(char *)esi
esi += 1
if al == 0:
    jump 0x400478
else:
    jump 0x400394
```

#### sub_400394

```
xor     al, al
mov     rdi, rsi
inc     rsi
scasb
jz      loc_400478

mov     al, 0
call    print
mov     rdi, rsi
inc     rsi
scasb
jnz     short sub_40035C
```

```python
al = *(char *)esi
esi += 1
if al == 1: # 0x4003A3
    print(0)
    al = *(char *)esi
    esi += 1
    if al == 0: # 0x40035C
        jump 0x40035C
    else: # 0x4003B3
        jump 0x4003B3 # (0->40035C, 1->400104)
else: # 0x400478
    jump 0x400478
```

정리하면 다음과 같이 동작한다.

```python
output = ''

def sub_40035C(bit):
    if bit:
        return sub_400346
    else:
        return sub_4003CD

def sub_4003CD(bit):
    global output
    output += '0'
    if bit:
        return sub_400370
    else:
        return sub_4003E1

def sub_400346(bit):
    global output
    output += '1'
    if bit:
        return sub_400457
    else:
        return sub_4003F3

def sub_400370(bit):
    global output
    output += '0'
    if bit:
        return sub_4003F3
    else:
        return sub_40037E

def sub_4003E1(bit):
    if bit:
        return sub_40037E
    else:
        return sub_400461

def sub_4003F3(bit):
    global output
    output += '1'
    if bit:
        return sub_4003A3
    else:
        return sub_40037E

def sub_400394(bit):
    if bit:
        return sub_4003A3
    else:
        return sub_400478

def sub_4003A3(bit):
    global output
    output += '0'
    if bit:
        return sub_4003B3
    else:
        return sub_40035C

def sub_40037E(bit):
    if bit:
        return sub_400394
    else:
        return sub_400478

def sub_4003B3(bit):
    global output
    output += '0'
    if bit:
        return sub_4003C7
    else:
        return sub_40035C

def sub_4003C7(bit):
    global output
    output += '1'
    if bit:
        return sub_40035C
    else:
        return sub_40011B

def sub_40011B(bit):
    if bit:
        return sub_40035C        
    else:
        return sub_400461

def sub_400461(bit):
    global output
    output += '0'
    if bit:
        return sub_400478
    else:
        return sub_400442

def sub_400478(bit):
    global output
    output += '1'
    if bit:
        return sub_4003B3
    else:
        return sub_400442

def sub_400442(bit):
    if bit:
        return sub_4003B3
    else:
        return sub_4003C7

def sub_400457(bit):
    if bit:
        return sub_4003A3
    else:
        return sub_40037E

def hash(ipt):
    global output
    output = ''
    func = sub_40035C
    ipt = int.from_bytes(ipt, 'little')
    i = 0
    while len(output) < 0x2e:
        func = func((ipt >> i) & 1)
        i += 1

    return output


ipt = b'asdfasdf\n'
print(hash(ipt))
```

이제 주어진 2진수 값이 나오도록 비트를 하나씩 구성해주면 된다.

#### sol.py

```python
from pwn import *
from collections import deque
from Crypto.Util.number import long_to_bytes
output = ''

def sub_40035C(bit):
    if bit:
        return sub_400346, -1
    else:
        return sub_4003CD, -1

def sub_4003CD(bit):
    if bit:
        return sub_400370, 0
    else:
        return sub_4003E1, 0

def sub_400346(bit):
    if bit:
        return sub_400457, 1
    else:
        return sub_4003F3, 1

def sub_400370(bit):
    if bit:
        return sub_4003F3, 0
    else:
        return sub_40037E, 0

def sub_4003E1(bit):
    if bit:
        return sub_40037E, -1
    else:
        return sub_400461, -1

def sub_4003F3(bit):
    if bit:
        return sub_4003A3, 1
    else:
        return sub_40037E, 1

def sub_400394(bit):
    if bit:
        return sub_4003A3, -1
    else:
        return sub_400478, -1

def sub_4003A3(bit):
    if bit:
        return sub_4003B3, 0
    else:
        return sub_40035C, 0

def sub_40037E(bit):
    if bit:
        return sub_400394, -1
    else:
        return sub_400478, -1

def sub_4003B3(bit):
    if bit:
        return sub_4003C7, 0
    else:
        return sub_40035C, 0

def sub_4003C7(bit):
    if bit:
        return sub_40035C, 1
    else:
        return sub_40011B, 1

def sub_40011B(bit):
    if bit:
        return sub_40035C, -1     
    else:
        return sub_400461, -1

def sub_400461(bit):
    if bit:
        return sub_400478, 0
    else:
        return sub_400442, 0

def sub_400478(bit):
    if bit:
        return sub_4003B3, 1
    else:
        return sub_400442, 1

def sub_400442(bit):
    if bit:
        return sub_4003B3, -1
    else:
        return sub_4003C7, -1

def sub_400457(bit):
    if bit:
        return sub_4003A3, -1
    else:
        return sub_40037E, -1

def dfs(func, cur, idx, target):
    global found, ans
    if found or len(cur) > 0x10*8:
        return

    for i in range(2):
        dest, bit = func(i)
        if bit == -1:
            dfs(dest, str(i) + cur, idx, target)
        elif bit == target[idx]:
            if idx + 1 < len(target):
                dfs(dest, str(i) + cur, idx+1, target)
            else:
                found = True
                cur = str(i) + cur
                ans = long_to_bytes(int(cur, 2))[::-1]
                return

def unhash(target):
    target = deque([int(x) for x in target])
    dfs(sub_40035C, '', 0, target)

p = process("./original.baby_bear", stdin=PTY)
p.recvuntil("Baby bear says: ")
target = p.recvline()[:-1].decode()

ans = ''
found = False
unhash(target)

p.sendafter("What do you say?", ans)
p.interactive()
```

```
$ python3 sol.py
[+] Starting local process './original.baby_bear': pid 3044
[*] Switching to interactive mode
 0011111010001010011010000101100011111001011101
Baby bear is thinking...

"Yeah, that sounds like what I was thinking", baby bear said.
Here's your flag: flag{test_flag}
```

### papa bear (482pts)

#### Description

```
Papa bear loves knitting, and even more so taking thin wires and spinning them together to make a strong, bushy rope.
Code:
 ______ _______ ______ _______ ______ _______ _______ ______
(_____ \ (_______)(_____ \ (_______) (____ \ (_______)(_______)(_____ \
_____) ) _______ _____) ) _______ ____) ) _____ _______ _____) )
| ____/ | ___ || ____/ | ___ | | __ ( | ___) | ___ || __ /
| | | | | || | | | | | | |__) )| |_____ | | | || | \ \
|_| |_| |_||_| |_| |_| |______/ |_______)|_| |_||_| |_|
dWWW=- dWWMWWWWWMWMb dMMWWWWWWWWWb -=MMMb
dWMWP dWWWMWWWMMWMMMWWWWWMMMMMMWMMMWWWMMMb qMWb
WMWWb dMWWMMMMMMWWWWMMWWWMWWWWWWMMWWWWMWMWMMMWWWWb dMMM
qMMWMWMMMWMMWWWMWMMMMMMMMWMMMMWWWMMWWMWMWMMWWMWWWWMWWMMWMMWP
QWWWWWWWMMWWWWWWWMMWWWWMMWP QWWWMWMMMMWWWWWMMWWMWWWWWWMP
QWMWWWMMWWMWMWWWWMWWP QWWMWWMMMWMWMWWWWMMMP
QMWWMMMP QMMMMMMP
```

`papa_bear`가 주어진다.

#### sub_60172B (main)

```c++
int __cdecl __noreturn main(int argc,
  const char ** argv,
    const char ** envp) {
  __int64 v3; // rcx
  char ipt; // al
  const char * nextArg; // rsi
  const char ** v6; // rdx
  __int64 cnt; // r11
  signed __int64 v8; // rax
  signed __int64 v9; // rax

  ipt = * (_BYTE * ) argv;
  nextArg = (char * ) argv + 1;
  if (ipt) {
    sub_401116( * (__int64 * ) & argc, (__int64) nextArg, (__int64) envp, v3);
    do
      sub_6016F4();
    while (cnt != 1);
    main(argc, (const char ** ) nextArg, v6);
  }
  v8 = sys_write(
    0,
    "   ______   _______  ______   _______      ______   _______  _______  ______\n"
    "  (_____ \\ (_______)(_____ \\ (_______)    (____  \\ (_______)(_______)(_____ \\\n"
    "   _____) ) _______  _____) ) _______      ____)  ) _____    _______  _____) )\n"
    "  |  ____/ |  ___  ||  ____/ |  ___  |    |  __  ( |  ___)  |  ___  ||  __  /\n"
    "  | |      | |   | || |      | |   | |    | |__)  )| |_____ | |   | || |  \\ \\\n"
    "  |_|      |_|   |_||_|      |_|   |_|    |______/ |_______)|_|   |_||_|   |_|\n"
    "\n"
    "            dMMM=-        dMMMMMMMMMMMb  dMMMMMMMMMMMb        -=MMMb\n"
    "          dMMMP       dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMb        qMMb\n"
    "          MMMMb   dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMb    dMMM\n"
    "          qMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMP\n"
    "            QMMMMMMMMMMMMMMMMMMMMMMMMMP  QMMMMMMMMMMMMMMMMMMMMMMMMMMP\n"
    "              QMMMMMMMMMMMMMMMMMMMP          QMMMMMMMMMMMMMMMMMMMP\n"
    "                     QMMMMMMP                         QMMMMMMP\n"
    "\n",
    0x3B9 uLL);
  v9 = sys_exit(0);
}
```

`argv`에 입력한 길이만큼 `main`이 다시 호출된다.

입력한 글자에 따라 `sub_401116` 함수에서 `rcx`가 설정되고 그만큼 `sub_6016F4` 함수가 호출된다.

#### sub_401116

```
// 첫번째 입력이 al에 들어감
mov     cl, 0BAh
jmp     short loc_40111B

loc_40111B:
mov     r8b, al
jmp     short loc_401124

loc_401124:
mul     cl
mov     r11, 7EB5EB00AEB06B1h
cmp     ax, 4D04h
jmp     short loc_40113C

loc_40113C:
jz      loc_4000F6 // al * 0xba == 0x4d04인지 비교
jmp     short loc_401145

loc_4000F6:
mov     al, 4Ah ; 'J'
mov     r11, 0AEB07B1BF498F34h
mov     cl, 7
jmp     short nullsub_13 // al = 0x4a, cl = 7로 설정하고 리턴

loc_401145:
mov     al, r8b
jmp     short loc_40114E
...
```

글자에 따라 `al`, `cl`값을 다르게 설정해준다.

bruteforce로 입력값에 따른 `al`, `cl`을 뽑아올 수 있다.

#### sub_6016F4

```
call    sub_6016AA

loc_6016F9:
lea     r9, [rax+0C300h]
mov     al, 4Dh ; 'M'
xchg    rbx, rdi
mov     rcx, offset sub_6016AA
sub     rcx, rdi
repne scasb // rdi를 rdi부터 'M'이 나오는 주소로 업데이트
lea     rdx, [rax+0Ah]
test    r9b, 1
cmovnz  rax, rdx // rax = 0x4d if (r9b & 1) else 0x4d + 0x0a
jrcxz   loc_601758 // 문자열 출력하고 종료

dec     rdi
stosb
xchg    rbx, rdi
jmp     short near ptr loc_6016F9+4 // 리턴
```

`rbx` 레지스터의 초기값은 `0x6012f1`이고 이 주소는 프로그램이 종료되기 전에 출력되는 문자열의 주소다.

'M' : 0x4d

'W' : 0x4d + 0xa

출력되는 문자열은 `0x6012f1` ~ `0x6016a9`이므로 이 함수는 `r9b`의 최하위 비트에 따라 출력값의 일부를 'M' 또는 'W'로 변경한다

#### sub_6016AA

```
mov     r8, rbx
add     rbx, 1038h
add     r8, 3B9h
ror     rbx, 9
cmp     bh, 8
mov     rbx, offset sub_6016AA
cmovz   rbx, r8
add     rbx, 0FFFFFFFFFFFFFC47h
mov     byte ptr ds:sub_6016AA, 0C3h
ret
```

`rbx` 레지스터값을 설정해준다.

`mov byte ptr ds:sub_6016AA, 0C3h` 때문에 함수가 호출된 뒤 다시 호출하면 그냥 리턴된다.

#### solution

목표는 description에 있는 문자열이 출력되도록 하는 것으로 보인다.

입력으로 `M`이 `W`로만 변하므로 각 글자에 대해 몇 번째 위치의 `M`이 변하는지 알아내고 출력이 description과 같게 나오게끔 문자를 배치해주면 된다.

#### sol.py

```python
import re
import shlex
import string
from pwn import *
context.log_level='error'

def init():
    global tbl
    p = process(["gdb", "papa_bear"])
    execute = lambda x: p.sendlineafter("pwndbg>", x, timeout=0.5)

    execute("b*0x601737")
    for c in string.printable[:-5]:
        execute(f"r {shlex.quote(c)}")
        execute("i r cl")
        cl = int(p.recvline().split()[1], 16)
        tbl[c] = cl

def go(ipt):
    p = process(["./papa_bear", ipt], stdin=PTY)
    res = re.sub('[^MW]', '', p.recvall().decode())
    p.close()
    return res

def dfs(ipt, plen, cl):
    print(ipt)
    res = go(ipt)

    if target == res[:len(target)]:
        print("found!")
        print(ipt)
        exit()
        
    elif target.startswith(res[:plen+cl]):
        for c, cnt in tbl.items():
            dfs(ipt+c, plen+cl, cnt)

target = '''dWWW=- dWWMWWWWWMWMb dMMWWWWWWWWWb -=MMMb
dWMWP dWWWMWWWMMWMMMWWWWWMMMMMMWMMMWWWMMMb qMWb
WMWWb dMWWMMMMMMWWWWMMWWWMWWWWWWMMWWWWMWMWMMMWWWWb dMMM
qMMWMWMMMWMMWWWMWMMMMMMMMWMMMMWWWMMWWMWMWMMWWMWWWWMWWMMWMMWP
QWWWWWWWMMWWWWWWWMMWWWWMMWP QWWWMWMMMMWWWWWMMWWMWWWWWWMP
QWMWWWMMWWMWMWWWWMWWP QWWMWWMMMWMWMWWWWMMMP
QMWWMMMP QMMMMMMP'''
target = re.sub('[^MW]', '', target)

tbl = {}
init()

for c, cnt in tbl.items():
    dfs(c, 0, cnt)
```

```
$ python3 sol.py
...
found!
HackTM{F4th3r bEaR s@y$: Smb0DY Ea7 My Sb3VE}
```

### mama bear (499pts)

#### Description

```
Despite Goldilocks' bad encounters with the bear family, mama bear seems to like her, and they’ve been talking using cryptography. Papa bear remembers hearing her say: “Haha more like 8ba409960881fbab676e7e4a47447770b365d57c186169286b2f064d0b434bf6”

Can you find out what she actually told Goldilocks?

P.S. to make your search easier, baby bear has noticed Goldilocks always starts her passwords with a capital X and ends them with a capital W.
```

`mama_bear`가 주어진다.

password는 X로 시작하고 W로 끝난다고 한다.

```
$ ./mama_bear 

  ███▄ ▄███▓ ▄▄▄       ███▄ ▄███▓ ▄▄▄          ▄▄▄▄   ▓█████ ▄▄▄       ██▀███
 ▓██▒▀█▀ ██▒▒████▄    ▓██▒▀█▀ ██▒▒████▄       ▓█████▄ ▓█   ▀▒████▄    ▓██ ▒ ██▒
 ▓██    ▓██░▒██  ▀█▄  ▓██    ▓██░▒██  ▀█▄     ▒██▒ ▄██▒███  ▒██  ▀█▄  ▓██ ░▄█ ▒
 ▒██    ▒██ ░██▄▄▄▄██ ▒██    ▒██ ░██▄▄▄▄██    ▒██░█▀  ▒▓█  ▄░██▄▄▄▄██ ▒██▀▀█▄
 ▒██▒   ░██▒ ▓█   ▓██▒▒██▒   ░██▒ ▓█   ▓██▒   ░▓█  ▀█▓░▒████▒▓█   ▓██▒░██▓ ▒██▒
 ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ░  ░ ▒▒   ▓▒█░   ░▒▓███▀▒░░ ▒░ ░▒▒   ▓▒█░░ ▒▓ ░▒▓░
 ░  ░      ░  ▒   ▒▒ ░░  ░      ░  ▒   ▒▒ ░   ▒░▒   ░  ░ ░  ░ ▒   ▒▒ ░  ░▒ ░ ▒░
 ░      ░     ░   ▒   ░      ░     ░   ▒       ░    ░    ░    ░   ▒     ░░   ░
        ░         ░  ░       ░         ░  ░    ░         ░  ░     ░  ░   ░
                                                    ░

       ʕ•ᴥ•ʔ        ___________________________
   ___/ \ /\ ___   \                           \
  / `/___Y__Y   \   \  Hello Goldilocks! Let's |
  (  (__ \__)   |    \ do some secret-ing this |
  |  /  \       /    | time. What do you want  |
  \______>-____/     | the password to be?     |
     | ( H ) |       \_________________________/
    /  -----  \                                                        ______
                                                                      /      \
                                     ____________________________     | *  * |
                                    /                           /     |  /   |
                                    | The password is aaaaaaaa /      | ---  |
                                    \_________________________/       \__  _/
                                                                        /  \
                                                                       /    \
       ʕ•ᴥ•ʔ        __________________________
   ___/ \ /\ ___   \                          \
  / `/___Y__Y   \   \  Very well. Now tell me |
  (  (__ \__)   |    \ your secret and I'll   |
  |  /  \       /    | maul it for you. GRRR! |
  \______>-____/     \________________________/
     | ( H ) |                                                         ______
    /  -----  \                                                       /      \
                             ____________________________________     | *  * |
                            /                                   /     |  /   |
                            | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa /      | ---  |
                            \_________________________________/       \__  _/
                                                                        /  \
                                                                       /    \
       ʕ•ᴥ•ʔ        _____________________________________
   ___/ \ /\ ___   \                                     \
  / `/___Y__Y   \   \   Haha more like                   |
  (  (__ \__)   |    \  7fcf7f80ffb07fcf004f004f807f7fcf |
  |  /  \       /     | 7fcf803000008030ffffffb07fcf7f80 |
  \______>-____/      \__________________________________/
     | ( H ) |
    /  -----  \
```

마지막 출력값이 `8ba409960881fbab676e7e4a47447770b365d57c186169286b2f064d0b434bf6`이 되도록 하는 입력을 찾으면 될 것 같다.

#### analysis

`0x601b87`에 password를, `0x60155e`에 secret을 입력받는다.

`start` 함수에서 read, write 함수를 제외하면 `sub_400486` 함수가 남는다.

#### sub_400486

```c++
__int64 sub_400486() {
  char * v0; // rsi
  char * v1; // rdi
  char v2; // al
  char v3; // al
  char v4; // al
  char v5; // al
  char v6; // al
  char v7; // al
  unsigned __int8 v8; // al
  _QWORD * v9; // rdi
  _QWORD * v10; // rdi
  char v11; // al
  unsigned __int8 v12; // al
  char v13; // al
  unsigned __int8 v14; // al
  char * v15; // r8
  char ** v16; // rdi
  unsigned __int64 v17; // rax
  _QWORD * v18; // rdi

  *(_QWORD * ) & pw = password;
  sub_4003F7();
  v0 = (char * ) off_601589; // v0 = 0x6015a1
  v1 = (char * ) sub_601B93;
  while (1) {
    if (v1 >= & byte_602B93)
      LABEL_17:
      JUMPOUT(0x4003D7 LL); // Error
    v2 = * v0++;
    v3 = v2 - 0x21;
    if (!v3)
      break;
    v4 = v3 - 5;
    if (v4) {
      v5 = v4 - 8;
      if (v5) {
        v6 = v5 + 1;
        if (v6) {
          v7 = v6 + 10;
          if (v7) {
            v8 = v7 - 13;
            if (v8 >= 0x2B u)
              goto LABEL_17;
            * v1 = -96;
            v9 = v1 + 1;
            * v9++ = & secret[v8];
            * v9 = 0x240488CCFF48 LL;
            v1 = (char * ) v9 + 6;
          } else {
            v13 = * v0++;
            v14 = v13 - 0x30;
            if (v14 >= 0x2B u)
              goto LABEL_17;
            v15 = & secret[v14];
            *(_WORD * ) v1 = 0xA166;
            v16 = (char ** )(v1 + 2);
            * v16++ = v15;
            *(_DWORD * ) v16 = __ROR4__(pw & 7, 8) | 0xC8C166;
            v16 = (char ** )((char * ) v16 + 4);
            *(_WORD * ) v16 = 0xA366;
            v16 = (char ** )((char * ) v16 + 2);
            * v16 = v15;
            v1 = (char * )(v16 + 1);
          }
        } else {
          *(_QWORD * ) v1 = 0xA2C4FF24048A LL;
          v10 = v1 + 6;
          v11 = * v0++;
          v12 = v11 - 48;
          if (v12 >= 0x2B u)
            goto LABEL_17;
          * v10 = & secret[v12];
          v1 = (char * )(v10 + 1);
        }
      } else {
        v17 = __rdtsc();
        *(_WORD * ) v1 = 0x90909F90000C00EB LL >> (v17 & 0x30);
        v1 += 2;
      }
    } else {
      qmemcpy(v1, & loc_400516, 0x47 uLL);
      v1 += 0x47;
    }
  }
  *(_WORD * ) v1 = 0xB848;
  v18 = v1 + 2;
  * v18++ = & loc_40063D;
  *(_WORD * ) v18 = 0xE0FF;
  off_601589 = v0;
  return ((__int64(__fastcall * )(char * , char * )) sub_601B93)((char * ) v18 + 2, v0);
}
```

`0x6015a1`에 저장되어 있는 값에 따라 분기가 다르게 된다.

분석해보면 다음과 같이 동작한다.

```python
sub_4003F7() # password 글자에 따라 arr 설정
v0 <- [0x601589] # 초기값 0x6015a1
v1 <- 0x601B93
while True:
    if v1 >= 0x602B93:
        raise Exception()
    v2 = v0.popleft()
    if v2 == 0x21: # '!'
        break
    elif v2 == 0x26: # '&' 
        qmemcpy(v1, & loc_400516, 0x47 uLL);
        v1 += 0x47;
    elif v2 == 0x2e: # '.'
        # ??
        v17 = __rdtsc();
        *(_WORD * ) v1 = 0x90909F90000C00EB LL >> (v17 & 0x30);
        v1 += 2;
    elif v2 == 0x2d: # '-'
        v1.push6(0xA2C4FF24048A)
        v11 = v0.popleft()
        if 0x30 <= v13 < 0x5B:
            v1.push8(&secret[v11 - 0x30])
        else:
            raise Exception()
    elif v2 == 0x23: # '#'
        v13 = v0.popleft()
        if 0x30 <= v13 < 0x5B:
            v1.push2(0xa166)
            v1.push8(&secret[v13 - 0x30])
            v1.push4(__ROR4__(pw & 7, 8) | 0xC8C166)
            v1.push2(0xa366)
            v1.push8(&secret[v13 - 0x30])
        else:
            raise Exception()
    elif 0x30 <= v2 < 0x5B: # '0' ~ 'Z'
        v1.push1(0xa0)
        v1.push8([&secret[v2 - 0x30])
        v1.push6(0x240488CCFF48)
    else:
        raise Exception()

[0x6015a1] <- v0
sub_601B93()
```

`0x6015a1`부터 써져있는 opcode를 이용해 `0x601B93`을 조작하고 마지막에 `sub_601B93()`에서 코드를 실행한다.

#### sub_4003F7

```c++
char __fastcall sub_4003F7()
{
  unsigned __int8 pw; // al
  char v1; // r9
  char result; // al
  __int64 v3; // [rsp+0h] [rbp-8h]

  v3 = 0x30201LL;
  byte_601B8F = *((_BYTE *)&v3 + (pw & 3));
  *(_DWORD *)((char *)&v3 + (pw & 3)) = *(_DWORD *)((char *)&v3 + (pw & 3) + 1);
  v1 = (unsigned __int16)(0x56 * ((unsigned __int64)pw >> 2)) >> 8;
  byte_601B90 = *((_BYTE *)&v3 + (unsigned __int8)((pw >> 2) - 3 * v1));
  *(_DWORD *)((char *)&v3 + (unsigned __int8)((pw >> 2) - 3 * v1)) = *(_DWORD *)((char *)&v3
                                                                               + (unsigned __int8)((pw >> 2) - 3 * v1)
                                                                               + 1);
  byte_601B91 = *((_BYTE *)&v3 + (v1 & 1));
  result = *((_BYTE *)&v3 + !(v1 & 1));
  byte_601B92 = result;
  return result;
}
```

`0x601B8f`에 있는 값을 변경한다.

디버깅해보면 password 한 글자에 따라 [0, 1, 2, 3]이 순서만 바뀌어서 저장된다.

#### parse.py

```python
from pwn import *
context.arch = 'amd64'

with open("mama_bear", "rb") as f:
    e = f.read()

opcodes = e[0x15A1:0x1B93]

def parse(opcodes):
    offset = 0
    code = b''
    addrs = []
    while True:
        if opcodes[offset] == ord('!'):
            break
        elif opcodes[offset] == ord('&'):
            code += e[0x516:0x516+0x47]
            offset += 1
        elif opcodes[offset] == ord('-'):
            offset += 1
            code += pack(0xA2C4FF24048A, 6*8) + p64(0xdeadbeef)
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            offset += 1
        elif opcodes[offset] == ord('#'):
            offset += 1
            x = ror(ord('W') & 7, 8, 4*8) # ord('W')는 password 값에 따라 달라짐
            code += pack(0xa166, 2*8) + p64(0xdeadbeef) + pack(0x00C8C166 | x, 4*8) + pack(0xa366, 2*8) + p64(0xdeadbeef)
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            offset += 1
        else:
            code += p8(0xa0) + p64(0xdeadbeef) + pack(0x240488CCFF48, 6*8)
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            offset += 1

    code = disasm(code)
    code = code.replace("0xdeadbeef", '{}')
    code = code.format(*addrs)

    return code


with open('output.txt', 'w') as f:
    for opcode in opcodes.split(b'!')[:-1]:
        print(f"[+] {(opcode + b'!').decode()}", file=f)
        print(parse(opcode + b'!'), file=f)
        print(file=f)
        print(file=f)
```

결과가 너무 길어서 각 opcode가 어떤 역할을 하는지 분석했다...

`!`     : return

`-INT`  : 스택에서 pop한 값을 `secret[INT - 0x30]`에 저장

`#INT`  : `secret[INT - 0x30:INT - 0x30 + 2]`를 `pw & 7`만큼 ror하여 `secret[INT - 0x30]`에 저장

`INT`   : `secret[opcode - 0x30]`을 스택에 push

`&`는 아래와 같은 연산을 한다.

```
0:   66 5b                   pop    bx
2:   b9 08 00 00 00          mov    ecx, 0x8 // 8회 반복
7:   48 31 c0                xor    rax, rax
a:   86 f8                   xchg   al, bh // al, bh, bl = x[1], 0, x[0]

c:   88 c2                   mov    dl, al // dl = x[1]
e:   88 de                   mov    dh, bl // dh = x[0] 
                                            -> dx = x[0] || x[1]
10:   48 83 e0 01             and    rax, 0x1
14:   48 83 e3 01             and    rbx, 0x1
18:   40 8a bc 43 8f 1b 60 00         mov    dil, BYTE PTR [rbx+rax*2+0x601b8f] // tmp = [(x[0] & 1) + (x[1] & 1)*2 + 0x601b8f]
20:   40 88 fe                mov    sil, dil
23:   40 d0 ee                shr    sil, 1
26:   88 d0                   mov    al, dl
28:   24 fe                   and    al, 0xfe
2a:   40 08 f0                or     al, sil // i = (x[1] & 0xfe) | (tmp >> 1)
2d:   40 80 e7 01             and    dil, 0x1 
31:   88 f3                   mov    bl, dh
33:   80 e3 fe                and    bl, 0xfe
36:   40 08 fb                or     bl, dil // j = (x[0] & 0xfe) | (tmp & 1)
39:   d0 c0                   rol    al, 1 // rol(i)
3b:   d0 c3                   rol    bl, 1 // rol(j)
3d:   e2 cd                   loop   0xc 

3f:   88 c7                   mov    bh, al
41:   66 c1 c3 08             rol    bx, 0x8
45:   66 53                   push   bx
```

```
10:   48 83 e0 01             and    rax, 0x1
14:   48 83 e3 01             and    rbx, 0x1
18:   40 8a bc 43 8f 1b 60 00         mov    dil, BYTE PTR [rbx+rax*2+0x601b8f]
```

`dil`은 `0x601b8f` ~ `0x601b8f + 3`까지 가능하다. (tmp는 0~3중 하나)

```
pwndbg> x/4c 0x601b8f
0x601b8f:       2 '\002'        1 '\001'        3 '\003'        0 '\000'
```

위 연산을 정리하면 다음과 같다.

```python
arr = [?, ?, ?, ?] # 0 ~ 3
res = [stack.pop1(), stack.pop1()]

for i in range(8):
    tmp = arr[(res[0] & 1) + (res[1] & 1)*2]   # tmp = 0b00 ~ 0b11
    res[1] = rol((res[1] & 0xfe) | (tmp >> 1), 1, 8)
    res[0] = rol((res[0] & 0xfe) | (tmp & 1), 1, 8)

bx = (res[0] << 8) | res[1] # swap
push2(bx)
```

```python
def parse2(opcodes):
    global stack
    offset = 0
    output = ''
    while True:
        if opcodes[offset] == ord('!'):
            output += 'return\n'
            break
        elif opcodes[offset] == ord('&'):
            x, y = stack.pop(), stack.pop()
            output += f'&({x}, {y})\n'
            stack += [f'ENC({x})', f'ENC({y})']
            offset += 1
        elif opcodes[offset] == ord('-'):
            offset += 1
            output += f'secret[{opcodes[offset] - 0x30}] = {stack.pop()}\n'
            offset += 1
        elif opcodes[offset] == ord('#'):
            offset += 1
            output += f'secret[{opcodes[offset] - 0x30}:{opcodes[offset] - 0x30 + 2}] = ror(secret[{opcodes[offset] - 0x30}:{opcodes[offset] - 0x30 + 2}], pw & 7, 16)\n'
            offset += 1
        else:
            stack.append(f'secret[{opcodes[offset] - 0x30}]')
            offset += 1

    return output
```

출력 결과가 push, pop하는 과정을 보기 편하게 `=`으로 줄여버려서 실제 동작이랑은 다르다.

다시 분석해보면 `pw & 7`이 맨 마지막에만 사용되는데 마지막 `pw`가 `W`라는게 주어졌기 때문에 신경쓰지 않아도 된다.

-> [0, 1, 2, 3] 순서가 바뀌는 배열만 bruteforce 해주면 돼서 `(4!) ** 6` 가지의 경우의 수를 고려하면 된다.

#### sol.py

[https://ctf.harrisongreen.me/2020/hacktm/mama_bear/](https://ctf.harrisongreen.me/2020/hacktm/mama_bear/) 를 참고했다.

```python
from z3 import *
from queue import deque

with open("mama_bear", "rb") as f:
    e = f.read()

opcodes = e[0x15A1:0x1B93]

def tokenizer(opcodes: str):
    res = []
    opcodes = deque(opcodes)
    while opcodes:
        opcode = opcodes.popleft()
        if opcode == '!':
            res.append(opcode)
        elif opcode == '&':
            res.append(opcode)
        elif opcode == '-':
            opcode += opcodes.popleft()
            res.append(opcode)
        elif opcode == '#':
            opcode += opcodes.popleft()
            res.append(opcode)
        else:
            res.append(opcode)
    
    return res

def go(opcode, pw):
    global stack
    for op in opcode:
        if op == '!':
            return
        
        elif op.startswith('-'):
            secret[ord(op[1]) - 0x30] = stack.pop()
        
        elif op.startswith('#'):
            idx = ord(op[1]) - 0x30
            
            val = Concat(secret[idx+1], secret[idx])
            val = RotateRight(val, 7)
            
            secret[idx] = Extract(7, 0, val)
            secret[idx+1] = Extract(15, 8, val)

        elif op.startswith('&'):
            res = [stack.pop(), stack.pop()]
            for i in range(8):
                idx = (res[0] & 1) + (res[1] & 1)*2
                tmp = Extract(7, 0, LShR(arr[pw], ZeroExt(3*8, 8*idx))) & 3
                res[1] = RotateLeft((res[1] & 0xfe) | LShR(tmp, 1), 1)
                res[0] = RotateLeft((res[0] & 0xfe) | (tmp & 1), 1)
            stack += [res[1], res[0]]
        
        else:
            stack.append(secret[ord(op[0]) - 0x30])

    return

ops = []
for opcode in opcodes.split(b'!')[1:-1]:
    ops.append(tokenizer((opcode + b'!').decode()))

s = Solver()

password = [BitVec('p%d' % i, 8) for i in range(8)]
secret = [BitVec('s%d' % i, 8) for i in range(32)]
orig_secret = [c for c in secret]
arr = Array('box', BitVecSort(8), BitVecSort(4*8))

s.add(password[0] == ord('X'))
s.add(password[7] == ord('W'))

for c in password:
    s.add(And(0x20 <= c,c <= 0x7f))

for c in orig_secret:
    s.add(And(0x20 <= c,c <= 0x7f))

stack = []
for i in range(8):
    go(ops[i], password[i])

target = bytes.fromhex("8ba409960881fbab676e7e4a47447770b365d57c186169286b2f064d0b434bf6")

for i in range(len(target)):
    s.add(secret[i] == target[i])

s.add(orig_secret[0] == ord('H'))
s.add(orig_secret[1] == ord('a'))
s.add(orig_secret[2] == ord('c'))
s.add(orig_secret[3] == ord('k'))

s.check()

m = s.model()
print(''.join([chr(m[x].as_long()) for x in orig_secret]))
```

```
$ python3 sol.py 
HackTM{By3_bYE_G0Ld!l0cKS_~mama}
```

z3를 안 쓰고 bruteforce를 잘 짜면 1 ~ 2시간 정도 걸리는 것 같다.

### PLOP (488pts)

#### Description

```
Author: trupples

I’ve been playing around with mathy obfuscation, see if you can break this one!

P.S. there are multiple “flags” the binary would say are correct, but only one of them matches the flag format.
```

`plop`이 주어진다.

```shell
$ ./plop
 /--------------------------\ 
 |                          | 
 | Welcome to my challenge! | 
 |                          | 
 \--------------------------/ 

Lemme check your flag :asdf
Thank you! We'll get back to you later with the results.

The lab is checking your flag (asdf).....
The results are in: Meh try again :/
```

입력을 받고 6초정도 있다가 프로그램이 종료된다.

gdb로 돌려보면 `0x555555400d30`에서 segmentation fault가 뜨면서 터진다.

```
 ► f 0   0x555555400d30
   f 1   0x5555554009a3
   f 2   0x7ffff7fe0f6b _dl_fini+523
   f 3   0x7ffff7e138a7 __run_exit_handlers+247
   f 4   0x7ffff7e13a60 on_exit
   f 5   0x7ffff7df108a __libc_start_main+250
```

backtrace에서 `_dl_fini`를 확인할 수 있다.

#### .fini_array

```
.fini_array:0000000000201D50 _fini_array     segment qword public 'DATA' use64
.fini_array:0000000000201D50                 assume cs:_fini_array
.fini_array:0000000000201D50                 ;org 201D50h
.fini_array:0000000000201D50 off_201D50      dq offset sub_B90       ; DATA XREF: init+13↑o
.fini_array:0000000000201D58                 dq offset sub_980
.fini_array:0000000000201D60                 dq offset sub_9B0
.fini_array:0000000000201D60 _fini_array     ends
```

`main`이 종료된 뒤 `sub_9B0` -> `sub_980` -> `sub_B90` 순서로 호출된다.

#### sub_9B0

```c++
void __fastcall sub_9B0()
{
  __int64 addr; // rdi
  char *v1; // rsi
  __int64 i; // rcx
  struct sigaction sigact; // [rsp+0h] [rbp-A8h] BYREF
  unsigned __int64 canary; // [rsp+98h] [rbp-10h]

  canary = __readfsqword(0x28u);
  if ( mmap((void *)0x1337000, 0x1000uLL, 3, 50, 0, 0LL) != (void *)0x1337000 )
    exit(0);
  addr = 0x1337000LL;
  v1 = ipt;
  for ( i = 25LL; i; --i )                      // memcpy(ipt, 0x1337000, 0x19*4)
  {
    *(_DWORD *)addr = *(_DWORD *)v1;
    v1 += 4;
    addr += 4LL;
  }
  sigact.sa_handler = (__sighandler_t)sub_C40;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0x40000004;
  sigaction(SIGSEGV, &sigact, 0LL);
  if ( __readfsqword(0x28u) != canary )
    main();
}
```

`0x1337000`에 메모리를 할당하고 입력값을 복사한다.

이 함수에서 `SIGSEGV`에 대한 핸들러가 `sub_C40`으로 설정된다.

#### sub_C40

메모리를 할당하고 `sub_1550`를 호출한다.

`sub_1550`에서 `*addr = 0xC390909090909090LL;`를 통해 opcode를 쓴다는 것을 유추할 수 있다.

어떤 opcode가 써지는지 확인하기 위해 `sub_1550`에 breakpoint를 걸고 확인해봤다.

gdb에서 `handle SIGSEGV pass nostop`를 실행하고 `$code+0x1550`에 breakpoint를 설정해 디버깅할 수 있다.

`sub_1550`을 호출할 때마다 인자가 바뀌어서 스크립트를 이용했다.

```python
from pwn import *
context.log_level="error"

p = process(["gdb", "plop"])

execute = lambda x: p.sendlineafter("pwndbg>", x, timeout=0.5)

def init():
    execute("starti")
    execute("code")
    execute("handle SIGSEGV nostop pass")

def recv():
    res = p.recvuntil("pwndbg>", drop=True, timeout=0.5)
    p.sendline()
    return res.decode()

def go(cnt):
    execute("x/30i $rdi")
    res = recv()
    print(f"[{cnt}] call rdi")
    print(res)
    execute("continue")

    execute("x/10i $rax")
    res = recv()
    print(f"[{cnt}] jump rax")
    print(res)

    if "rax,QWORD PTR ds:0x1337100" in res:
        raise Exception()
    else:
        execute("continue")

    return res

init()

breakpoints = [0x15b2, 0x15bf]
for bp in breakpoints:
    execute(f"b*$code+{bp}")

execute("run << a")

try:
    cnt = 1
    while True:
        go(cnt)
        cnt += 1
except:
    p.interactive()
```

결과를 분석해보면 8라운드 동안 입력값 8바이트와 상수값을 이용해 ror, rol, xor 연산을 해 0이 아니면 `0x1337064`에 1을 저장한다.

`jmp rax`는 마지막 라운드를 제외하고 segmentation fault를 내서 다시 핸들러를 호출하도록 되어있다.

아래 흐름을 보면 `0x1337064`에 저장된 값에 따라 `0x20202c`에 저장되는 값이 달라진다.

```
► 0x55555540153f    mov    rax, qword ptr [0x1337100] # 마지막 라운드 끝
   0x555555401547    push   rax
   0x555555401548    ret    
    ↓
   0x555555400be0    cmp    byte ptr [0x1337064], 0
   0x555555400be8    setne  byte ptr [rip + 0x20143d] # 0x20202c
   0x555555400bef    jmp    0x555555400bef
    ↓
   0x555555400bef    jmp    0x555555400bef # 무한루프
```

```
sub_C00 proc near
; __unwind {
sub     rsp, 8
cmp     cs:byte_20202C, 0
lea     rax, aMehTryAgain ; "Meh try again :/"
lea     rdx, aYouDidIt  ; "You did it!"
lea     rsi, aTheResultsAreI ; "\nThe results are in: %s\n"
mov     edi, 1
cmovnz  rdx, rax
xor     eax, eax
call    ___printf_chk
movzx   edi, cs:byte_20202C ; status
call    _exit
; }
```

`sub_C40`에서 무한루프를 돌다가 SIGALRM 핸들러가 호출되어 `byte_20202C`값에 따라 다른 출력이 나온다.

#### solution

위에 작성한 python 스크립트 실행 결과를 z3 solver로 풀어주면 플래그를 얻을 수 있다.

#### sol.py

```python
from z3 import *
from pwn import *
from Crypto.Util.number import long_to_bytes

s = Solver()

ans = [BitVec(f'ans{i}', 8*8) for i in range(8)]

for i in range(8):
    for j in range(8):
        c = Extract((j+1)*8 - 1, j*8, ans[i])
        s.add(And(0x20 <= c, c < 0x7f))

# flag format
s.add(Extract(7, 0, ans[0]) == ord('H'))
s.add(Extract(15, 8, ans[0]) == ord('a'))
s.add(Extract(23, 16, ans[0]) == ord('c'))
s.add(Extract(31, 24, ans[0]) == ord('k'))
s.add(Extract(39, 32, ans[0]) == ord('T'))
s.add(Extract(47, 40, ans[0]) == ord('M'))
s.add(Extract(55, 48, ans[0]) == ord('{'))

# round 1
tmp = RotateLeft(ans[0], 0xe) ^ 0xdc3126bd558bb7a5

# round 2
# s.add(tmp == 0)
s.add(ans[1] == RotateRight(tmp ^ 0x76085304e4b4ccd5, 0x28))

# round 3
s.add(RotateLeft(ans[2], 0x3e) ^ 0x1cb8213f560270a0 == tmp)

# round 4
s.add(RotateLeft(ans[3], 2) ^ 0x4ef5a9b4344c0672 == tmp)

# round 5
s.add(ans[4] == RotateRight(tmp ^ 0xe28a714820758df7, 0x2d))

# round 6
s.add(RotateLeft(ans[5], 0x27) ^ 0xa0d78b57bae31402 == tmp)

# round 7
s.add(RotateRight(ans[6] ^ rol(0x4474f2ed7223940, 0x35, 64), 0x35) == tmp)

# round 8
s.add(ans[7] == RotateRight(tmp ^ 0xb18ceeb56b236b4b, 0x19))

while True:
    if s.check() != sat:
        break

    m = s.model()
    res = [int(m[i].as_long()) for i in ans]

    print(''.join(map(lambda x: x.to_bytes(8, 'little').decode(), res)))
    check = And([ans[i] == res[i] for i in range(8)])
    s.add(check == False)
```

```shell
$ python3 sol.py
HackTM{PolynomialLookupOrientedProgramming_sounds_kinda_shit_xd}
```
