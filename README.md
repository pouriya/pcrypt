# Simple encryption utility for files/directories
This script (en|de)crypts directories/files by using AES (CBC) algorithm. It also generates a new VI for each encryption.

![pcrypt](https://user-images.githubusercontent.com/20663776/103262540-788a3400-49ba-11eb-9f6d-4f3db347d78c.png)


# Usage
```sh
~ $ pcrypt -h
usage: pcrypt [-h] [-d DIRECTORY] [-f FILE] [-D] [-E] [--show-password]
              [--no-color]

Simple encryption utility for files/directories

optional arguments:
  -h, --help       show this help message and exit
  -d DIRECTORY     In decryption mode it should be directory name that
                   contains the encrypted file andin encryption mode it should
                   be the directory that you want to encrypt all or one of its
                   files. Note that in encryption mode if -f is not set, it
                   encrypt all internal directories too. Its default value is
                   current working directory or /p/test/A.
  -f FILE          The filename to (en|de)crypt.
  -D               Switchs to decryption mode. If -f is not set, It tries to
                   decrypt its default encrypted file name or
                   'b1gs3cr3t.pcrypt'
  -E               Switchs to encryption mode (which is the default
                   behaviour). The default encrypted file name for folders is
                   'b1gs3cr3t.pcrypt'
  --show-password  Shows your password when you type/paste it.
  --no-color       Makes it print plain text instead of colorized text.
```

# Installation
You must have `python3` installed.
```sh
~/path/to/cloned/pcrypt $ chmod a+x pcrypt.py && sudo ln -sf $PWD/pcrypt.py /usr/local/bin/pcrypt
```
or
```sh
curl -sSf https://raw.githubusercontent.com/pouriya/pcrypt/21.01.01/pcrypt.py > pcrypt && chmod a+x pcrypt && sudo cp pcrypt /usr/local/bin/pcrypt
```
