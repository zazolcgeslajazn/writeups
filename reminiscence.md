# TCP1P 2023 CTF - Reminiscence (Misc)

> 500 points (1 solve)\
> Author: lunaroa
> 
> We've detected unusual network traffic within our network. Upon inspection, it turns out that a malicious actor gained access to one of our staff's credentials and logged into the server. Could you analyze what actually occurred?
>
> Solution: unx, fkania2\
> Writeup: unx

## Reconnaissance
We are given a netcat command. The remote server asks for answers regarding the incident. There is also a zip containing pcap file.

## Questions

### Q1: What TCP protocol/service is captured in the network packet? Please enter the port as well. Format: ftp:1337
Opening the pcap in Wireshark, clicking the first packet, and following its TCP stream shows it's an SSH communication. The server port is `23425`

![image](https://github.com/zazolcgeslajazn/writeups/assets/28658966/8f56f32a-bd1a-474e-9e05-8d3d1c4ea032)


### Q2: What is the SSH version that could be affected by a security bug? Is it a client or server? Format: OpenSSH_6.9_server
Trying both the versions visible in pcap was enough: `OpenSSH_4.3_client`

![image](https://github.com/zazolcgeslajazn/writeups/assets/28658966/3ceac8b6-7ea8-433d-82a1-8fe2cb7ffb92)


### Q3: How many SSH/SFTP sessions occurred during the incident? Also, how many successfully executed commands were there during the last session? Format: 1_3

At this point, we know decrypting the SSH traffic was necessary. Given the challenge name and vulnerable OpenSSH version, it must be some ancient vulnerability. Also since it's on the client side,  it's most likely a weak encryption vulnerability. Searching Google for some older articles, we found [this one](https://www.cr0.org/progs/sshfun/) describing a vulnerability in debian's OpenSSL, which generated weak keys easy to bruteforce.

#### Used tools
Two tools had to be launched: [ssh-kex-keygen](https://github.com/trou/ssh_kex_keygen/blob/master/README) written in C which brute-forced the keys, and [ssh_decoder](https://github.com/jjyg/ssh_decoder) which decrypted ssh traffic from raw TCP dumps.

##### ssh-kex-keygen
ssh-kex-keygen is written around specific, vulnerable OpenSSL version: 0.9.8. Fortunately all the libraries required for compilation are embedded in the repository, so we only had to modify the command from Makefile to include these libraries, use given linker and cross-compile for 32bit.\
`gcc -W -o keygen main.c -I$PWD/openssl-0.9.8e/openssl-0.9.8e/include -L$PWD/ubuntu-7.04-x86-patched -l:libssl.so.0.9.8 -l:libcrypto.so.0.9.8 -l:libdl.so.2 -l:libc.so.6 -l:libz.so.1 -l:libcrypt.so.1 -Wl,ubuntu-7.04-x86-patched/ld-linux.so.2 -m32`

##### ssh_decoder
ssh_decoder is a ruby helper for ssh-kex-keygen, which handles extracting the right values from ssh traffic, providing them to ssh-kex-keygen, and then decrypting the ssh traffic. One modification had to be made in it to work on recent ruby version. `allhex` getter defined on String was returning an array instead of a hex string in some cases, which confused ssh-kex-keygen. All we had to do was to add `.first` to all affected arguments, for example: `'G' => groupinfo[:g].allhex` to `'G' => groupinfo[:g].allhex.first`

#### Decrypting traffic (finally)
Now, it was as simple as following ssh_decoder readme:
```
How to use :
- get a capture (PCAP)
- use tcpick -wRC -wRS session.pcap 
- ruby ssh_decoder.rb *.dat
- ???
- profit.
```

tcpick showed us the first answer: `4 tcp sessions detected`. The second answer could be found by analyzing the last session file from server side.

![image](https://github.com/zazolcgeslajazn/writeups/assets/28658966/771a1743-ff01-4867-8fd8-cb37fb75bcee)


Final answer: 4_8

### Q4: What is the name of the malicious script uploaded during the SFTP session?
The file along with its name is available in one of the decrypted session files: `y6V71q8PnAdxCmEaDGtsrSwRcMbhl9UIBiXfJ23v_eo504TuWkFONjzLHpYKQgZ`. In the last session we can see that `.pyc` extension was appended to it, and then executed: we'll need that later.

### Q5: What are the username and password used by the malicious actor? Format: username_password
These are presented to us by ssh_decoder:
```
{:username=>"pi",
 :nextservice=>"ssh-connection",
 :auth_method=>"password",
 :change=>0,
 :password=>"MYQRqNHZ51"}
```

### Q6: Could you tell me the name of the file affected by the malicious script?
We didn't want to analyze the .pyc script yet, so we tried every file visible in ssh sessions. 

![image](https://github.com/zazolcgeslajazn/writeups/assets/28658966/3b0b94e6-e95c-4583-bfbe-2204d2a48468)

`/tmp/message` was the answer.

### Q7: What was the content of the message file before it was encrypted?
Now the python script had to be analyzed.
#### Decompiling
We can see that it's executed using python2 on the server, so we used [uncompyle6](https://pypi.org/project/uncompyle6/) for .pyc decompilation. When I saw the code, i wanted to scream.
```python
# uncompyle6 version 3.9.0
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 2.7.18 (default, Feb 18 2023, 11:16:16) 
# [GCC 12.2.1 20230201]
# Embedded file name: y6V71q8PnAdxCmEaDGtsrSwRcMbhl9UIBiXfJ23v_eo504TuWkFONjzLHpYKQgZ.py
# Compiled at: 2023-10-13 05:03:15
(lambda _a=dir, _b=getattr, _c=globals, _d=type: (lambda _e=_d([]), _f=_d(()), _g=_d({}): (lambda _h=_c()[_e(_c())[_a == _b]]: (lambda _i=_c()[_e(_c())[_a == _b]], _ww=_a.__doc__, _yy=_a == _b, _xx=_a == _a: (lambda _j=_b(_i, _ww[(~_xx * ~_xx) ** (~_xx * ~_xx) + ~_xx * ~_xx * ~_xx * ~_xx + -~_xx * ~_xx * ~_xx - _xx] + _ww[(~_xx * ~_xx) ** (~_xx * ~_xx) + ~_xx * ~_xx * ~_xx * ~_xx + -~_xx * ~_xx * ~_xx - _xx] + _ww[_xx] + _ww[59] + _ww[100] + _ww[5] + _ww[-~_xx] + _ww[10] + _ww[(~_xx * ~_xx) ** (~_xx * ~_xx) + ~_xx * ~_xx * ~_xx * ~_xx + -~_xx * ~_xx * ~_xx - _xx] + _ww[(~_xx * ~_xx) ** (~_xx * ~_xx) + ~_xx * ~_xx * ~_xx * ~_xx + -~_xx * ~_xx * ~_xx - _xx]): (lambda _zz=_b(_j(_ww[19] + _ww[461] + _ww[19]), _ww[38] + _ww[-~_xx] + _ww[30] + _ww[192])[_yy]: (lambda _k=_j(_zz[44] + _zz[21]), _l=_j(_zz[14] + _zz[22] + _zz[-~_xx] + _zz[59] + _zz[20] + _zz[44] + chr(46) + _zz[14] + _zz[35] + _zz[59] + _zz[29] + _zz[43] + _zz[22] + chr(46) + _zz[11] + _zz[16] + _zz[23]), _m=_j(_zz[14] + _zz[22] + _zz[-~_xx] + _zz[59] + _zz[20] + _zz[44] + chr(46) + _zz[32] + _zz[20] + _zz[35] + _zz[30] + chr(46) + _zz[9] + _zz[17] + _zz[12] + _zz[12] + _zz[35] + _zz[10] + _zz[63]), _n=_j(_zz[56] + _zz[30] + _zz[35] + _zz[28]), _o=_j(_zz[63] + _zz[30] + _zz[44] + _zz[28]), _p=_j(_zz[35] + _zz[44]), _q=_j(_zz[28] + _zz[17] + _zz[21] + _zz[43] + _zz[3] + _zz[47]): (lambda _r=_b(_o, _zz[63] + _zz[30] + _zz[44] + _zz[28])(_zz[15] + _zz[43] + _zz[21] + _zz[21] + _zz[17] + _zz[63] + _zz[43]), _s=_b(_k, _zz[49] + _zz[22] + _zz[17] + _zz[10] + _zz[12] + _zz[44] + _zz[15]), _t=_b(_p, _zz[44] + _zz[59] + _zz[43] + _zz[10]), _u=_b(_q, _zz[28] + _zz[3] + _zz[47] + _zz[43] + _zz[10] + _zz[26] + _zz[44] + _zz[12] + _zz[43]): (lambda _v=lambda _w, _x, _y: _b(_b(_b(_b(_l, _zz[14] + _zz[35] + _zz[59] + _zz[29] + _zz[43] + _zz[22]), _zz[11] + _zz[16] + _zz[23]), _zz[10] + _zz[43] + _zz[24])(_w, -~_xx, _y), _zz[43] + _zz[10] + _zz[26] + _zz[22] + _zz[-~_xx] + _zz[59] + _zz[20])(_b(_b(_b(_m, _zz[32] + _zz[20] + _zz[35] + _zz[30]), _zz[9] + _zz[17] + _zz[12] + _zz[12] + _zz[35] + _zz[10] + _zz[63]), _zz[59] + _zz[17] + _zz[12])(_x, ~_xx * ~_xx * ~_xx * ~_xx)) + _w + _y: (lambda _z=_b(_i, _zz[15] + _zz[17] + _zz[59]), _aa=_b(_i, _zz[22] + _zz[17] + _zz[10] + _zz[63] + _zz[43]), _ab=_b(_i, _zz[22] + _zz[43] + _zz[12] + _zz[49] + _zz[26] + _zz[43]), _ac=_b(_i, _zz[26] + _zz[29] + _zz[22]), _ad=_b(_i, _zz[30] + _zz[35] + _zz[21] + _zz[20]), _ae=_b(_i, _zz[30] + _zz[43] + _zz[10]): (lambda _af=lambda _ag: _ab((lambda _ah, _ai: _ah + [_ag[_ai:_ai + ~_xx * ~_xx * ~_xx * ~_xx]]), _aa(_yy, len(_ag), ~_xx * ~_xx * ~_xx * ~_xx), []): (lambda _aj=_af(_b(_n, _zz[26] + _zz[44] + _zz[15] + _zz[59] + _zz[22] + _zz[43] + _zz[21] + _zz[21])(_u(_b(_t(_r[_yy], _zz[22] + _zz[28]), _zz[22] + _zz[43] + _zz[17] + _zz[12])()))): _b(_i, _zz[59] + _zz[22] + _zz[35] + _zz[10] + _zz[20])(_u(_b(_b(_i, _zz[21] + _zz[20] + _zz[22])(), _zz[55] + _zz[44] + _zz[35] + _zz[10])(_z((lambda _ak: _v(_s(~_xx * ~_xx * ~_xx * ~_xx), _ak, _s(~_xx * ~_xx * ~_xx * ~_xx))), _aj)))))())())())())())())())())())())())()
```
Huge lambda statement. Using deobfuscators was probably pointless, so I began to analyze it manually.
#### Deobsfucation (kind of) and analysis
The most helpful step was to discover all the used strings.
- `_ww[x]` is `dir.__doc__[x]`,
- after replacing all `_ww` strings, we can see that `_zz[x]` is `sys.argv[1]`, name of the file.


Further *very* manual deobfuscation (removing nested lambdas, naming variables) led us to the following script flow:
- find the file with `message` in its path,
- base64 encode and zlib compress the contents,
- split into 16byte chunks,
- encrypt it using AES:
```python
lambda key, data, iv:
    aes.cipher.AES.new(key, 2, iv).encrypt(
    padding.Util.Padding.pad(data, 16)) + key + iv:
```
- every chunk was now: [32]data (because of padding) + [16]key + [16]iv
- join the chunks, base64 it again, and print it out to console

#### Reversing encryption
The encryption keys were in the output along with encrypted data, so decryption was trivial.
Output used here was present in the last decoded session file.
```python
from Crypto.Cipher import AES
from Crypto.Util import Padding
import zlib
import base64

def decrypt_data(data):
    key = data[-32:-16]
    iv = data[-16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(data[:-32])
    unpadded_data = Padding.unpad(decrypted_data, 16)
    return unpadded_data

def main():
    encrypted_data = base64.b64decode("<output from session>")
    encrypted_chunks = [encrypted_data[i:i+64] for i in range(0, len(encrypted_data) - 32, 64)]
    
    decrypted_chunks = [decrypt_data(chunk) for chunk in encrypted_chunks]
    decompressed_data = zlib.decompress(b"".join(decrypted_chunks))
    original_data = base64.b64decode(decompressed_data)

    print(original_data)

if __name__ == "__main__":
    main()
```

This outputs the PNG file which contains this QR code:

![image](https://github.com/zazolcgeslajazn/writeups/assets/28658966/34544f73-1aa2-403d-a746-771dd202f387)

Decoding reveals us the answer: `is_this_truly_confidential`

## Following all the answers, the flag was revealed:

![image](https://github.com/zazolcgeslajazn/writeups/assets/28658966/39cf1cfe-8413-478b-93e3-33deb3129e47)

At the end, ours was the only one solution :D
