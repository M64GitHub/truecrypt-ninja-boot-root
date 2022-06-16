> This is an old security research project, dating back to 2012/13. It was released to only a few people/groups for obvious reasons. My goal back then was to "totally" reverse engineer and exploit all security measures. As truecrypt is gone, I decided to publish it openly. I have left a secret pointer within the PDF to proove ownership. 
> The original upload is still at http://www.k00n.byethost7.com/.

# NBRK - Ninja Boot Rootkit (for TrueCrypt hidden OS)

An in depth analysis by creating a working boot rootkit for the truecrypt hidden operating system 
(various windows flavours), with in mem bootsector patching, revealing all passwords in pre kernel- 
(mbr, chainloader), kernel- ("kernel password painter"), and user space (via ndis exploit or 
ntfs password writer), ...  
Additional to it, a whole flexible boot chain loader "purple chain" was presented, including possibilities to boot any sector(s) on the truecrypt encrypted disk, to boot from CDROM after decryption, and lots of fancy stuff ...


### "This document presents the results of a research about the infection-resistency of the truecrypt hidden operating system against the threats of boot rootkits. It targets the questions whether the state of the art malware could persistently infect the hidden OS from the outside (ie decoy OS), and if yes – how."

[Full Disclosure PDF](https://github.com/M64GitHub/truecrypt-ninja-boot-root/blob/main/revealing_the_hidden.pdf)

all source code will follow. meanwhile some teaser screenshots. full disclosure in the PDF (incl source).

## Ninja Boot Rootkit in action on WIN 7/32, XP :

![NBRK1](http://m64.rocks/ninja-boot-root/1.png "NBRK1")

![NBRK1](http://m64.rocks/ninja-boot-root/7.png "NBRK1")

![NBRK1](http://m64.rocks/ninja-boot-root/6.png "NBRK1")

![NBRK1](http://m64.rocks/ninja-boot-root/5.png "NBRK1")

```
## Windows XP Kernel Password Painter =8] : 
```

![NBRK1](http://m64.rocks/ninja-boot-root/10.png "NBRK1")
