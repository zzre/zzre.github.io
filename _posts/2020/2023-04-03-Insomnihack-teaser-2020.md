---
title : "Insomnihack teaser 2020"
categories : ['2020', 'Insomni\'hack teaser 2020']
---

## Reversing

### Kaboom - 94pts (57 solves)

#### Description

```
Defuse the bomb!
```

[https://github.com/Pusty/writeups/tree/master/InsomnihackTeaser2020](https://github.com/Insomnihack/Teaser-2020/tree/master/kaboom)

위 repository에서 `kaboom-161bddc63eadbf39092b495ac888af7dc6fa5106c612bd8a4a62761f98ff4d3c.exe`가 주어지는 것 같다.

```console
> .\kaboom-161bddc63eadbf39092b495ac888af7dc6fa5106c612bd8a4a62761f98ff4d3c.exe
KABOOM!
```

일단 실행시켜봤는데 `KABOOM!`이라는 문자열을 출력하고 종료된다.

```console
$ file kaboom-161bddc63eadbf39092b495ac888af7dc6fa5106c612bd8a4a62761f98ff4d3c.exe 
kaboom-161bddc63eadbf39092b495ac888af7dc6fa5106c612bd8a4a62761f98ff4d3c.exe: PE32 executable (console) Intel 80386, for MS Windows, UPX compressed
```

바로 UPX unpack 해주고 분석을 시작해보자.

`shift + f12`로 string 탭에서 `KABOOM!`을 검색해 참조하는 곳을 찾았다.

#### main_0

{% raw %}
```c++
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  if ( argc < 2 || sub_402DF1(argv[1], aDefuse) || (v3 = sub_401523(aIns), sub_4011AE(aIns_0, aHttpsWwwYoutub, v3)) )
  {
    printf("%s", aKaboom);
    return 1;
  }
  else
  {
    printf("Congrats! The flag is %s\n", aHttpsWwwYoutub_0);
    return 0;
  }
}
```
{% endraw %}

#### ChatGPT

`sub_402DF1`를 봤는데 유명한 함수일 것 같아서 ChatGPT한테 그대로 물어봤다.

```
함수는 32비트 단위로 비교를 수행합니다. 비교는 작은 단위인 8비트와 16비트 단위로 세분화되며, 두 값이 같은 경우 다음 단위로 이동합니다. 함수는 두 번째 인수의 끝까지 비교를 수행하고, 그 결과에 따라 1, -1 또는 0을 반환합니다.
```

인자랑 설명을 보면 이 함수는 `strcmp`인 것 같다.

`sub_401523`도 물어보면 `strlen` 설명을 알려준다.

#### sub_4011AE

함수 길이가 길어서 ChatGPT한테 못 물어봤다.

{% raw %}
```c++
...
  switch ( len )
  {
    case 0u:
      return 0;
    case 1u:
      c1 = *str1;
      c2 = *str2;
      goto LABEL_348;
    case 2u:
      chk = *str1 - *str2;
      if ( !chk )
      {
        c1 = str1[1];
        c2 = str2[1];
        goto LABEL_348;
      }
...
LABEL_348:
    chk2 = c1 - c2;
    if ( chk2 )
      return 2 * (chk2 > 0) - 1; // 다르면 return 1 or -1
    return chk2; // 같으면 return 0
  }
```
{% endraw %}

일단 이 부분으로 `memcmp`로 추정했다.

#### 삽질

`printf("Congrats! The flag is %s\n", aHttpsWwwYoutub_0);` 부분을 보고

https://www.youtube.com/watch?v=oGJr5N2lgsQ 에 접속해봤는데 낚시였다.

그러면 `main_0` 조건을 패치해서 통과해도 가짜 플래그가 나와서 다른 곳으로 접근해야 한다..

#### UPX

감이 안와서 출제자 설명을 봤는데 UPX2 섹션 크기를 늘리고 code caving을 해놨다고 한다.

그래서 UPX unpack을 하면 UPX2 섹션 뒤의 코드가 날아가버려서 풀이가 불가능한 바이너리가 나오게 되는 것 같다...

{% raw %}
```python
'''
...
mov edx, [ebx+0x3c]    # 2. Get the address of kernel32.GetCommandLineA in edx
add edx, ebx
mov edx, [edx+0x78]
add edx, ebx
mov esi, [edx+0x20]
add esi, ebx
xor ecx, ecx
findGetCommandLineA:
inc ecx
lodsd
add eax, ebx
cmp dword ptr [eax], 0x43746547
jne findGetCommandLineA
cmp dword ptr [eax+0x4], 0x616d6d6f
jne findGetCommandLineA
cmp dword ptr [eax+0x8], 0x694c646e
jne findGetCommandLineA
cmp dword ptr [eax+0xc], 0x0041656e
jne findGetCommandLineA
mov esi, [edx+0x24]
add esi, ebx
mov cx, [esi+ecx*2]
dec ecx
mov esi, [edx+0x1c]
add esi, ebx
mov edx, [esi+ecx*4]
add edx, ebx           # edx = kernel32.GetCommandLineA


call edx               # 3. Test the value of the end of the command line (the last argument)
jmp beginSearchLastArg
loopSearchLastArg:
inc eax
beginSearchLastArg:
cmp byte ptr [eax], 0x00
jnz loopSearchLastArg
push 0x00
push 0x33e377fd
push 0xd7831bba
push 0x4ce1b463
push 0x42
pop ecx

testArg:
xor edx,edx
dec eax
add cl, byte ptr [eax]
cmp cl, byte ptr[esp]
je testOk        
or dl,1 # test fail

testOk:
inc esp
cmp byte ptr [esp], 0x00
jnz testArg              
pop ecx
cmp dl,0
jne jumpToOEP        # If the test fails, do nothing and return to OEP, get JEBAITED

decode:               # If you did not get JEBAITED, decode the original binary
mov al, byte ptr [originalBinary + ecx]
mov byte ptr [{} + ecx], al
mov byte ptr [originalBinary + ecx], 0x0
inc ecx
cmp ecx, {}
jb decode

jumpToOEP:
jmp {}
originalBinary:
'''.format(diff_start, diff_len, original_EP+1), vma=new_EP)
...
```
{% endraw %}

```
push 0x00
push 0x33e377fd
push 0xd7831bba
push 0x4ce1b463
push 0x42
```
에서 hex값들을 push하고 

`GetCommandLineA`로 마지막 인자 뒤부터 hex 값들로 검증을 한다.

이후 검증에 통과하면 `decode`로 제대로 된 flag가 출력될 수 있도록 한다.

#### sol.py

{% raw %}
```python
esp = [0x63, 0xB4, 0xE1, 0x4C, 0xBA, 0x1B, 0x83, 0xD7, 0xFD, 0x77, 0xE3, 0x33]
cl = 0x42
ans = ''

for i in range(len(esp)):
    ans += chr((esp[i] - cl) & 0xff)
    cl = esp[i]

print(ans[::-1])
```
{% endraw %}

{% raw %}
```console
$ python3 sol.py 
Plz&Thank-Q!
```

```console
> .\kaboom-161bddc63eadbf39092b495ac888af7dc6fa5106c612bd8a4a62761f98ff4d3c.exe defuse "Plz&Thank-Q!"
Congrats! The flag is INS{GG EZ clap PogU 5Head B) Kreygasm <3<3}
```
{% endraw %}

코드 안 보고 어떻게 풀어야할지.. 아직 모르겠다
