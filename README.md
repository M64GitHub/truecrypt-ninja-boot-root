

# NBRK - Ninja Boot Rootkit (for TrueCrypt hidden OS)

```
An in depth analysis by creating a working boot rootkit for the truecrypt hidden operating system 
(various windows flavours), with in mem bootsector patching, revealing all passwords in pre kernel- 
(mbr, chainloader), kernel- ("kernel password painter"), and user space (via ndis exploit or 
ntfs password writer), ... 


"This document presents the results of a research about the infection-resistency of the truecrypt 
hidden operating system against the threats of boot rootkits. It targets the questions whether 
the state of the art malware could persistently infect the hidden OS from the outside (ie decoy OS), 
and if yes – how."

all source code will follow. meanwhile some teaser screenshots. full disclosure in the PDF (incl source).
```

## Ninja Boot Rootkit in action on WIN 7/32, XP

![NBRK1](http://m64.rocks/ninja-boot-root/7.png "NBRK1")

![NBRK1](http://m64.rocks/ninja-boot-root/6.png "NBRK1")

![NBRK1](http://m64.rocks/ninja-boot-root/5.png "NBRK1")

```Windows XP Kernel Password Painter =8]
```

![NBRK1](http://m64.rocks/ninja-boot-root/10.png "NBRK1")
