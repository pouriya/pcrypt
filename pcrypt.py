#! /usr/bin/env python3

import struct
import tarfile
import os.path as path
from os import urandom, remove
from Crypto.Cipher import AES
from hashlib import sha256


DEFAULT_CHUNCK_SIZE = 256 * 1024
EXTENTION = '.pcrypt'
DEFAULT_ENCRYPTED_FILENAME = 'b1gs3cr3t' + EXTENTION
COLORS = {
    'red':    '\033[1;31m',
    'white':  '\033[1;37m',
    'gray':   '\033[1;30m',
    'yellow': '\033[1;33m',
    'reset':  '\033[0m'
}


def _open_file(filename, mode):
    try:
        fd = open(filename, mode)
    except Exception as reason:
        raise IOError('!Could not open file {!r}: {}'.format(input_filename, reason))
    return fd


def _maybe_remove_file(filename):
    # It may take a while for large files
    while True:
        try:
            path.exists(filename) and remove(filename) and print('{gray}Removed file {}{reset}'.format(filename, **COLORS))
        except KeyboardInterrupt:
            print(
                '{red}DO NOT TRY TO EXIT THE PROGRAM while it\'s removing its files{reset}'
                .format(**COLORS)
            )
            continue
        break


def encrypt_file(key, input_filename, output_filename, chunk_size=None):
    if chunk_size is None:
        chunk_size = DEFAULT_CHUNCK_SIZE

    iv = urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    input_fd = _open_file(input_filename, 'rb')
    input_file_size = path.getsize(input_filename)

    output_fd = _open_file(output_filename, 'wb')
    output_fd.write(struct.pack('<Q', input_file_size))
    output_fd.write(iv)

    encrypted_size = 0
    dots_in_line_count = 0
    print(
        '{white}Attempt to encrypt data{reset} {gray}to {!r}{reset}'.format(
            output_filename,
            **COLORS
        )
    )
    print('{gray}Printing a dot after encrypting each 10MB of data{reset}'.format(**COLORS))
    while True:
        chunk = input_fd.read(chunk_size)
        chunk_length = len(chunk)
        if chunk_length == 0:
            break
        if chunk_length % 16 != 0:
            chunk += b' ' * (16 - chunk_length % 16)
        try:
            output_fd.write(encryptor.encrypt(chunk))
        except Exception as reason:
            # Probably 'no space left' exception
            _maybe_remove_file(output_filename)
            raise IOError('!Could not write to output file {!r}: {}'.format(output_filename))
        encrypted_size += chunk_length
        # 0xA00000: 10MB
        if encrypted_size > 0xA00000:
            encrypted_size = 0
            print('.', end='', flush=True)
            dots_in_line_count += 1
            if dots_in_line_count >= 80:
                dots_in_line_count = 0
                print()
    print()
    input_fd.close()
    output_fd.close()
    print('{white}Encrypted{reset}'.format(**COLORS))


def decrypt_file(key, input_filename, output_filename, chunk_size=None):
    if not input_filename.endswith(EXTENTION):
        raise ValueError('!The file {!r} is not encrypted by pcrypt'.format(input_filename))
    if chunk_size is None:
        chunk_size = DEFAULT_CHUNCK_SIZE
    if path.exists(output_filename):
        raise ValueError('!Output file {!r} already exists'.format(output_filename))
    if not path.exists(input_filename):
        raise ValueError('!Could not found input file {!r}'.format(input_filename))

    input_fd = _open_file(input_filename, 'rb')
    output_file_size = struct.unpack('<Q', input_fd.read(struct.calcsize('Q')))[0]
    iv = input_fd.read(16)
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    output_fd = _open_file(output_filename, 'wb')

    decrypted_size = 0
    dots_in_line_count = 0
    print(
        '{white}Attempt to decrypt data{reset} {gray}to {!r}{reset}'.format(
            output_filename,
            **COLORS
        )
    )
    print('{gray}Printing a dot after encrypting each 10MB of data{reset}'.format(**COLORS))
    while True:
        chunk = input_fd.read(chunk_size)
        chunk_length = len(chunk)
        if chunk_length == 0:
            break
        try:
            output_fd.write(decryptor.decrypt(chunk))
        except Exception as reason:
            # Probably 'no space left' exception
            _maybe_remove_file(output_filename)
            raise IOError('!Could not write to output file {!r}: {}'.format(output_filename))

        decrypted_size += chunk_length
        # 0xA00000: 10MB
        if decrypted_size > 0xA00000:
            decrypted_size = 0
            print('.', end='', flush=True)
            dots_in_line_count += 1
            if dots_in_line_count >= 80:
                dots_in_line_count = 0
                print()
    print()
    input_fd.close()
    output_fd.truncate(output_file_size)
    output_fd.close()
    print('{white}Decrypted{reset}'.format(**COLORS))


def make_tar_archive(filenames, output_filename, path_prefix):
    if path.exists(output_filename):
        raise ValueError('!Output file {!r} already exists'.format(output_filename))

    try:
        tar = tarfile.open(output_filename, "w:gz")
    except Exception as reason:
        raise IOError('!Could not open tar archive {!r}: {}'.format(output_filename, reason))
    print('{gray}Attempt to make a tar archive{reset}'.format(**COLORS))
    for filename in filenames:
        print('{gray}Attempt to add {!r} to archive{reset}'.format(filename, **COLORS))
        try:
            tar.add(filename, arcname=path.relpath(filename, path_prefix))
        except Exception as reason:
            raise IOError('!Could not add file {!r} to tar archive: {}'.format(filename, reason))
    tar.close()


def untar_archive(input_filename):
    try:
        tar = tarfile.open(input_filename)
    except Exception as reason:
        print(
            '{gray}Could not open decrypted tar archive {!r}: {}{reset}'.format(
                input_filename,
                reason,
                **COLORS
            )
        )
        raise IOError('!Maybe the password is wrong!')

    def log_and_yield_members(members):
        for member in members:
            print(
                '{gray}Attempt to extract {!r} from tar archive{reset}'.format(
                member.name,
                **COLORS
                )
            )
            yield member
    print('{gray}Attempt to extract files from tar archive{reset}'.format(**COLORS))
    try:
        tar.extractall(members=log_and_yield_members(tar))
    except Exception as reason:
        raise IOError('!Could extract archive {!r}: {}'.format(input_filename, reason))


if __name__ == '__main__':
    import argparse
    from os import getcwd
    from time import time
    from getpass import getpass
    from glob import glob


    def read_password(show_password_in_prompt):
        text = '{yellow}Enter password: {reset}'.format(**COLORS)
        password = input(text) if show_password_in_prompt else getpass(prompt=text)
        print()
        # make it 32 bytes
        return sha256(password.encode()).digest()


    def should_we_stop():
        return input(
            '{white}Continue? [{yellow}y{reset}{white}/{reset}{yellow}n{reset}{white}]: {reset}'
            .format(**COLORS)
        ).lower() != 'y'


    def main(args, tmp_tar_filename):
        if args.decrypt:
            input_file = DEFAULT_ENCRYPTED_FILENAME if args.file is None else args.file
            input_file = path.join(args.directory, input_file)
            print('{white}Going to decrypt {!r}{reset}'.format(input_file, **COLORS))
            if should_we_stop():
                return
            decrypt_file(read_password(args.show_password_in_prompt), input_file, tmp_tar_filename)
            untar_archive(tmp_tar_filename)
        else:  # args.encrypt (which is default)
            if args.file is None:
                output_file = DEFAULT_ENCRYPTED_FILENAME
                if path.exists(output_file):
                    raise RuntimeError('!Encrypted file {!r} already exists'.format(output_file))
                input_files = [
                    x for x in \
                    glob(path.join(args.directory, '**'), recursive=True) \
                    if path.isfile(x)
                ]
                if input_files == []:
                    raise RuntimeError('!Could not found any file to encrypt')
                sorted(input_files)
                print('{white}Going to encrypt following files:{reset}'.format(**COLORS))
                for input_file in input_files:
                    print('{gray}{}{reset}'.format(input_file, **COLORS))
            else:
                input_file = path.join(args.directory, args.file)
                if not path.exists(input_file):
                    raise RuntimeError('!Input file {!r} does not exist'.format(input_file))
                output_file = input_file + EXTENTION
                if path.exists(output_file):
                    raise RuntimeError('!Encrypted file {!r} already exists'.format(output_file))
                input_files = [input_file]
                print(
                    '{white}Going to encrypt {gray}{!r}{reset}{reset}'.format(input_file, **COLORS)
                )
            if should_we_stop():
                return
            password = read_password(args.show_password_in_prompt)
            make_tar_archive(input_files, tmp_tar_filename, path.dirname(args.directory))
            encrypt_file(password, tmp_tar_filename, output_file)

    parser = argparse.ArgumentParser(description='Simple encryption utility for files/directories')
    parser.add_argument(
        '-d',
        default=getcwd(),
        dest='directory',
        help='In decryption mode it should be directory name that contains the encrypted file and' \
        'in encryption mode it should be the directory that you want to encrypt all or one of its' \
        ' files. Note that in encryption mode if -f is not set, it encrypt all internal directori' \
        'es too. Its default value is current working directory or %(default)s.'
    )
    parser.add_argument(
        '-f',
        default=None,
        dest='file',
        help='The filename to (en|de)crypt.'
    )
    parser.add_argument(
        '-D',
        action='store_true',
        default=False,
        dest='decrypt',
        help='Switchs to decryption mode. If -f is not set, It tries to decrypt its default encry' \
        'pted file name or {!r}'.format(DEFAULT_ENCRYPTED_FILENAME)
    )
    parser.add_argument(
        '-E',
        action='store_true',
        default=False,
        dest='encrypt',
        help='Switchs to encryption mode (which is the default behaviour). The default encrypted ' \
        'file name for folders is {!r}'.format(DEFAULT_ENCRYPTED_FILENAME)
    )
    parser.add_argument(
        '--show-password',
        action='store_true',
        default=False,
        dest='show_password_in_prompt',
        help='Shows your password when you type/paste it.'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        default=False,
        dest='no_color',
        help='Makes it print plain text instead of colorized text.'
    )
    args = parser.parse_args()
    if args.encrypt and args.decrypt:
        parser.error('Using -E and -D with each other is not allowed')
    if args.no_color:
        COLORS = {x[0]: '' for x in COLORS.items()}

    tmp_tar_filename = str(int(time())) + '.tar.gz'
    status_code = 0
    try:
        main(args, tmp_tar_filename)
    except KeyboardInterrupt:
        print()
        status_code = 1
    except Exception as reason:
        reason_str = str(reason)
        if reason_str[0] != '!':
            _maybe_remove_file(tmp_tar_filename)
            raise
        print('{red}{}{reset}'.format(reason_str[1:], **COLORS))
        status_code = 1
    _maybe_remove_file(tmp_tar_filename)
    exit(status_code)
