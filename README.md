# reverse-it-api

A quick and dirty tool to generate a SHA256 hash of a file and (optionally) check it against the reverse.it API.

## Requirements

Python3

The `requests` module.

A reverse.it API key. It's free.

## Usage

Move `config-example.py` to `config.py`. Add your API key to `config.py`. 

To _only_ generate the hash, run `python3 hash_gen.py /path/to/file`. 

To check the hash against the RIT API, run `python3 hash_gen.py /path/to/file -a`.

To see the MITRE info (if available), run `python3 hash_gen.py /path/to/file -a -m`. 

## Sample output

```
bash-3.2$ python3.6 hash_gen.py /Volumes/NEW\ VOLUME/endec-37.exe -a -m


[/] /Volumes/NEW VOLUME/endec-37.exe is a valid file


[/] SHA256 of file: bb8c2b7eb41a7e55fd07fdb454c041cfc1c573a71e10ffde8d7776c6ea9a0801


[/] Checking against API

Analysis for /Volumes/NEW VOLUME/endec-37.exe || SHA256: bb8c2b7eb41a7e55fd07fdb454c041cfc1c573a71e10ffde8d7776c6ea9a0801

Overall Stats:
==================================

Verdict: malicious

Threat Score: 100

Threat Level: 2

==================================
Details:

Malware Name: endec-37.exe

Malware Type: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows

Reverse IT Environment: Windows 7 64 bit

Total Number of Processes Spawned: 25

Domains Contacted:
bcmrh.net
bqkxhedn.net
cnrrkb.pw
dpvqsyboaxd.com
elcld.net
isnkbgaqlre.pw
jjfmsl.com
jtffo.pw
kfgyujjfs.pw
knngf.in
lhtqudc.in
maqzgb.pw
nrkhfmpen.in
ooflzt.com
qirblf.com
qsqvawgijy.pw
qxnurtklwrei.com
rujvxspetzl.pw
swneayrgkuug.pw
tyroqjgsbvq.com
ubchgyh.in
uincfo.pw
upjgfz.com
vlxrmqnmgyg.in
xatmj.net
xfqkpd.net
xhiksyts.pw
ylbhyv.pw
ytmnmbltkpf.in
zghcjna.in


===================================

MITRE INFO:



Tactic: Persistence

Technique: Kernel Modules and Extensions

Wiki Link: https://attack.mitre.org/wiki/Technique/T1215



Tactic: Persistence

Technique: Hooking

Wiki Link: https://attack.mitre.org/wiki/Technique/T1179



Tactic: Privilege Escalation

Technique: Process Injection

Wiki Link: https://attack.mitre.org/wiki/Technique/T1055



Tactic: Privilege Escalation

Technique: Hooking

Wiki Link: https://attack.mitre.org/wiki/Technique/T1179



Tactic: Defense Evasion

Technique: Process Injection

Wiki Link: https://attack.mitre.org/wiki/Technique/T1055



Tactic: Credential Access

Technique: Hooking

Wiki Link: https://attack.mitre.org/wiki/Technique/T1179



Tactic: Discovery

Technique: Application Window Discovery

Wiki Link: https://attack.mitre.org/wiki/Technique/T1010



Tactic: Discovery

Technique: Query Registry

Wiki Link: https://attack.mitre.org/wiki/Technique/T1012



Tactic: Discovery

Technique: Process Discovery

Wiki Link: https://attack.mitre.org/wiki/Technique/T1057



Tactic: Lateral Movement

Technique: Remote Desktop Protocol

Wiki Link: https://attack.mitre.org/wiki/Technique/T1076
```