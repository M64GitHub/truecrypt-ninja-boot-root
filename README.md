<img width="1328" alt="3" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/be664ea3-bfbe-4ad9-99f3-4dbf5f3f84f3"> 
This is an old security research project, dating back to 2012/13. My goal back then was to fully reverse engineer truecrypts protection and exploit all security measures. As truecrypt is gone, I decided to publish it openly. I have left a secret pointer within the PDF to proove ownership.  
The original upload is still at http://www.k00n.byethost7.com, and can be traced back by "the internet wayback machine".  

#### Relevant is only the [PDF](https://github.com/M64GitHub/truecrypt-ninja-boot-root/blob/main/revealing_the_hidden.pdf), which contains all the work, including the source code and the screenshots below.

## NBRK - Ninja Boot Rootkit (for TrueCrypt hidden OS)
 - The following document presents the results of a research about the infection-resistency of the truecrypt hidden operating system against the threats of boot rootkits. It targets the questions whether the state of the art malware could persistently infect the hidden OS from the outside (ie decoy OS), and if yes – how.

 - An in depth analysis by creating a working boot rootkit for the truecrypt hidden operating system 
(various windows flavours), with in mem bootsector patching, revealing all passwords in pre kernel- 
(mbr, chainloader), kernel- ("kernel password painter"), and user space (via ndis exploit or 
ntfs password writer), ...  

 - Additional to it, a whole flexible boot chain loader "purple chain" was presented, including possibilities to boot any sector(s) on the truecrypt encrypted disk, to boot from CDROM after decryption, and lots of fancy stuff ...

[Full Disclosure PDF](https://github.com/M64GitHub/truecrypt-ninja-boot-root/blob/main/revealing_the_hidden.pdf)

## Ninja Boot Root in full Effect
<img width="676" alt="7" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/47fac77a-6ecb-43a1-97e3-225dbc6ce012">

<img width="675" alt="6" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/689b8f8e-2e02-4a12-bec0-1d41f76c9367">

#### Kernel Panic Effect (turning bluescreen into purplescreen)
(NDIS exploit, triggered over network, for demo purposes)
<img width="676" alt="10" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/e9819653-f829-4cb3-bb37-9cd55e3173b0">

#### Effect of NTFS Password writer in 512 bytes 
(results in passwords printed by command.com for demo purposes):  
<img width="570" alt="5" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/8dfcc894-bb6b-4114-a532-25f309194c13">


## Purple Chain advanced Boot Environment
for research purposes

Screenshots shown randomly on Windows 7, and Windows XP (working on both systems)

Win XP  
<img width="1086" alt="1" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/f374f71f-eccc-4ddd-8bbb-fabc15baf7e3">

Win 7  
<img width="676" alt="8" src="https://github.com/M64GitHub/truecrypt-ninja-boot-root/assets/84202356/43a04412-2fc5-4c6c-a4db-94a90140f815">


