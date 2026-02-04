#!/bin/sh
user="$(gpg2 -qd /home/moo/test/gopherbook/moo.pass.asc)"
EXTEN="jpg"
mkdir -p ./cbzs
7z a -tzip -mem=AES256 -mx=9 ./cbzs/$1-others.cbz -p *.$EXTEN ComicInfo.xml
