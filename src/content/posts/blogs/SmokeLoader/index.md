---

title: SmokeLoader analysis
published: 2023-10-02
description: A writeup for Practical Car Hacking CTF Teaser.
tags: [Blogs, Malware]
category: Blogs
draft: false
---

> SmokeLoader is primarily a loader, and its main objective is to download or load a stealthier or more effective malware into the system.

**My impression:**
  + Anti-VM, Anti-Sandbox (vmware, vbox,...).
  + Anti-process (procexp64.exe, x32dbg.exe,...).
  + Anti-Debug (PEB ntGlobalFlag).
  + Encrypt String, C2,...
  + Payload Compressed (lsza, lznt1).
  + Obfuscated code.

**Execute flow:**
  + mal.bin -> stage_2.bin -> final_stage.bin

## Variant 1
  > sha256: [f656bec8181d8911220fbe23c86ad5e80b45b613990707ef8815482135e898ab](https://www.virustotal.com/gui/file/cef4f5f561b5c481c67e0a9a3dd751d18d696b61c7a5dab5ebb29535093741b4)
  - mal.bin:
    - Alloc memory, write shellcode into alloced mem, then execute it.
    - The data in new memory is a PE file, dump it and we will have stage_2.bin
  - stage_2.bin:
    - Load PE into IDA and look at the start func:
      ![image](pic/variant_1_start.png)
    - This is called ["opaque predicate"](https://en.wikipedia.org/wiki/Opaque_predicate). The program will jump to loc_402DE9+1 (you can verify by debug it) everytime, so we will patch it with jmp instruction.
    - [ida_script](https://github.com/AnduinBrian/malware_adventure/blob/SmokeLoader/SmokeLoader/ida_script_universal/ida_script.py#L12) -> patch_nop in this script will find jnz and jz pattern, after that it patch to jmp xxx and nop.
    - Body of function in Smokeloader will be encrypted with xor. It will decrypt the body first, execute it and re-encrypt the body. <br>
    ![image](pic/variant_1_func.png)
    - It resolve API by using djb2_hash, it travel through PEB structre to find handle of dll.
    - Enumerate all subkey of these key (Anti-VM):
      - System\CurrentControlSet\Enum\IDE
      - System\CurrentControlSet\Enum\SCSI
    - Final payload will be stored somewhere in stage_2, after some anti-* func we will some instruction that lead to final_stage location. In this example: final_stage data start at base + 0x53e3 and size is 0x2FDE.<br>
    ![image](pic/variant_1_size.png)
    - Data of final_stage will be xor with const (this time is 0x76186250), after xor we will have a buffer but it compressed, we need to decompress. This sample using lzsa2 to compress and decompress, you can verify it by looking the function after the xor function ([lzsa2](https://www.manhunter.ru/assembler/1593_raspakovka_dannih_v_formate_lzsa1_i_lzsa2_na_assemblere.html)) <br>
    ![image](pic/variant_1_lzsa2.png)
    - I use unicorn engine to emulate, the script [here](https://github.com/AnduinBrian/malware_adventure/blob/SmokeLoader/SmokeLoader/variant%201/Scripts/ida_uc_emu.py). The function [xor_dword](https://github.com/AnduinBrian/malware_adventure/blob/SmokeLoader/SmokeLoader/ida_script_universal/ida_script.py#L38) in the ida_script will be used for xor function i mention before.
    - First 4 bytes is the length of the compressed data (0x5400).
    - After run emu script. We have a binary, but not in PE format. We just need to fix 3 place:
      - First: edit to hex 4D 5A or text "MZ".
      - Sec: edit to hex C0.
      - Third: edit to hex 50 45 or text "PE". <br>
   ![image](pic/variant_1_pe.png)
  - stage_3:
    - In this stage, we will focus on how to dump config. We just looking for function that have xor (xor use alot in encrypt and decrypt) and find one function look like rc4.
    - Look at the function, we see that the function have 4 param:
      - 1st: data
      - 2nd: key
      - 3rd: data len
      - 4nd: key len (usually = 4) 
    - We will see a call instruction at 0x1800020E6, the param is pointer. After some RE, we will find out:<br>
      ![image](pic/variant_1_structure.png)
    - Now go ahead and write script to decrypt. We will have output: ```http://nusurionuy5ff.at/```. Xref the unk_1800011C0 and we will see a table look like c2_table [script](https://github.com/AnduinBrian/malware_adventure/blob/SmokeLoader/SmokeLoader/variant%201/Scripts/extract_conf.py#L29). Result:
    ```
      Python> extract_config(0x180001A90, 0xd)
        http://monsutiur4.com/
        http://nusurionuy5ff.at/
        http://moroitomo4.net/
        http://susuerulianita1.net/
        http://cucumbetuturel4.com/
        http://nunuslushau.com/
        http://linislominyt11.at/
        http://luxulixionus.net/
        http://lilisjjoer44.com/
        http://nikogminut88.at/
        http://limo00ruling.org/
        http://mini55tunul.com/
        http://samnutu11nuli.com/
    ```
    
## Variant 2
> sha256: [fc20b03299b8ae91e72e104ee4f18e40125b2b061f1509d1c5b3f9fac3104934](https://www.virustotal.com/gui/file/fc20b03299b8ae91e72e104ee4f18e40125b2b061f1509d1c5b3f9fac3104934)
  - Almost samething, but this time it use lznt1 to decompress (use RtlDecompressBuffer) (**We dont skip first 4 bytes anymore**). I wrote the [script](https://github.com/AnduinBrian/malware_adventure/blob/SmokeLoader/SmokeLoader/variant%202/Scripts/lznt1_decompress.py) to decompress the data.
  - The decrypt of stage_3 is only xor. <br>
  ![image](pic/variant_2_structure.png)
  - [Script](https://github.com/AnduinBrian/malware_adventure/blob/SmokeLoader/SmokeLoader/variant%202/Scripts/extract_config.py) here.
  
<div style="height: 300px; overflow-y: scroll;border: none">

```console
Python> extract_c2(0x180002810, 99, 0xe4)
    http://protest-01242505.tk/
    http://test-service012505.ru.com/
    http://test-service012505.pw/
    http://test-service012505.com/
    http://test-service012505.site/
    http://test-service012505.store/
    http://test-service01242505.ru/
    http://mytest-service012505.ru/
    http://test-service012505.su/
    http://test-service012505.info/
    http://test-service012505.net/
    http://test-service012505.tech/
    http://test-service012505.online/
    http://rutest-service012505.ru/
    http://test-service01dom2505.ru/
    http://test-service012505.website/
    http://test-service012505.xyz/
    http://test-service01pro2505.ru/
    http://test-service01rus2505.ru/
    http://test-service012505.eu/
    http://test-service012505.press/
    http://protest-service012505.ru/
    http://rustest-service012505.ru/
    http://test-service012505.net2505.ru/
    http://test-service012505.space/
    http://domtest-service012505.ru/
    http://mirtest-service012505.ru/
    http://test-service012505.org2505.ru/
    http://test-service012505.pp2505.ru/
    http://test-service012505.pro/
    http://test-service012505.host/
    http://test-service012505.fun/
    http://mostest-service012505.ru/
    http://toptest-service012505.ru/
    http://alltest-service012505.ru/
    http://vsetest-service012505.ru/
    http://newtest-service012505.ru/
    http://biotest-service012505.ru/
    http://test-service01shop2505.ru/
    http://test-service01info2505.ru/
    http://test-service01plus2505.ru/
    http://test-service01club2505.ru/
    http://test-service01torg2505.ru/
    http://test-service01land2505.ru/
    http://test-service01life2505.ru/
    http://test-service01blog2505.ru/
    http://megatest-service012505.ru/
    http://infotest-service012505.ru/
    http://besttest-service012505.ru/
    http://shoptest-service012505.ru/
    http://kupitest-service012505.ru/
    http://proftest-service012505.ru/
    http://clubtest-service012505.ru/
    http://mytest-service01242505.ru/
    http://rutest-service01242505.ru/
    http://test-service01stroy2505.ru/
    http://test-service01forum2505.ru/
    http://supertest-service012505.ru/
    http://protest-service01242505.ru/
    http://protest-01252505.ml/
    http://protest-01262505.ga/
    http://protest-01272505.cf/
    http://protest-01282505.gq/
    http://protest-01292505.com/
    http://protest-01302505.net/
    http://protest-01312505.org/
    http://protest-01322505.biz/
    http://protest-01332505.info/
    http://protest-01342505.eu/
    http://protest-01352505.nl/
    http://protest-01362505.mobi/
    http://protest-01372505.name/
    http://protest-01382505.me/
    http://protest-01392505.garden/
    http://protest-01402505.art/
    http://protest-01412505.band/
    http://protest-01422505.bargains/
    http://protest-01432505.bet/
    http://protest-01442505.blue/
    http://protest-01452505.business/
    http://protest-01462505.casa/
    http://protest-01472505.city/
    http://protest-01482505.click/
    http://protest-01492505.company/
    http://protest-01502505.futbol/
    http://protest-01512505.gallery/
    http://protest-01522505.game/
    http://protest-01532505.games/
    http://protest-01542505.graphics/
    http://protest-01552505.group/
    http://protest-02252505.ml/
    http://protest-02262505.ga/
    http://protest-02272505.cf/
    http://protest-02282505.gq/
    http://protest-03252505.ml/
    http://protest-03262505.ga/
    http://protest-03272505.cf/
    http://protest-03282505.gq/
    http://protest-05242505.tk/
```
</div>

<style>
  pre.astro-code.github-dark {
    margin: 0;
  }
</style>