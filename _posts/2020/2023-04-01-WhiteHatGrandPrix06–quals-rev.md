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

`flag` 함수는 다음과 같이 동작한다.

```
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

`data`를 복구하여 `whitehat.exe`를 실행하면 플래그를 출력할 것으로 보인다.

#### `SHF` 함수

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

`SHF`는 simple hash function의 약자인 것 같다.

`SHF`, `flag`함수를 분석해보았을 때 원본 `data`의 해시값이 플래그다.

`output.jpg`에서 `ptr[i][10]`과 swap된 부분만 복구하면 `data`를 얻을 수 있다.

#### solution

다음 순서로 `data`를 얻을 수 있다.

1. `main`함수에 주어진 조건과 `flag` 함수 인자로 전달되는 hash값으로 `ptr[i][10]` 복구
2. `swap`된 부분 복구

이후 `SHF(data)`를 계산해 flag를 얻을 수 있다.

#### sol.py

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





