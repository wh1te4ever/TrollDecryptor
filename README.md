# TrollDecryptor
Decrypt appstore apps for TrollStore

## How to use
1. Download and install TrollDecryptor from [Release](https://github.com/wh1te4ever/TrollDecryptor/releases)
2. Run appstore's app that you want to decrypt.
3. Enter app pid (You can get app pid from CocoaTop) and click Decrypt.
4. You can get decrypted-app.ipa from /var/mobile/Containers/Data/Application/(trolldecryptor uuid)/Documents

## How to build
1. Install Theos Development Kit.
2. Run below command and you can get TrollDecryptor.ipa
```
$ make package
```

## Credit / Thanks
- [dumpdecrypted](https://github.com/stefanesser/dumpdecrypted) by Stefan Esser
- [bfdecrypt](https://github.com/BishopFox/bfdecrypt) by BishopFox
