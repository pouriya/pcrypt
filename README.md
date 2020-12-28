# Simple encryption utility for files/directories
This script (en|de)crypts directories/files by using AES (CBC) algorithm. It also generates a new VI for each encryption.

![pcrypt]()


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
                   current working directory or /p/test/pcrypt.
  -f FILE          The filename to (en|de)crypt.
  -D               Switchs to decryption mode. If -f is not set, It tries to
                   decrypt its default encrypted file name or
                   'B1GS3CR3T.pcrypt'
  -E               Switchs to encryption mode (which is the default
                   behaviour). The default encrypted file name for folders is
                   'B1GS3CR3T.pcrypt'
  --show-password  Shows your password when you type/paste it.
  --no-color       Makes it print plain text instead of colorized text.
```

# Installation
You must have `python3` installed. Also if you want to use `clipboard` feature, you must install `pyperclip` library too.  
```sh
~/path/to/cloned/ppg $ chmod a+x pcrypt.py && sudo ln -sf $PWD/pcrypt.py /usr/local/bin/pcrypt
```
or
```sh
~ $ curl -sSf https://raw.githubusercontent.com/pouriya/pcrypt/20.12.28/pcrypt.py > /usr/local/bin/pcrypt && chmod a+x /usr/local/bin/pcrypt
```
