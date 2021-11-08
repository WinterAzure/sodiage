# This script is used to generate dictionary header file
# Dictionary location is /usr/share/dict/american-english 
from os.path import exists
from random import shuffle

F_HEADER='''
#ifndef __DICT_H
#define __DICT_H

static char* password_words[] = {
'''

F_TAIL='''
};


#endif
'''

DICTIONARY_LOCATION='/usr/share/dict/american-english'
WORDS_CHOOSED=list()

def check_word(word:str) -> bool:
    for i in (ord(x) for x in word):
        if not 97<=i<=121:
            return False
    return True

def main() -> None:
    if not exists(DICTIONARY_LOCATION):
        print('No dictionary file found.')
        exit(1)
    all_words=open(DICTIONARY_LOCATION,'r').readlines()
    shuffle(all_words)
    for number,word in enumerate(all_words):
        if check_word(word.strip()):
            WORDS_CHOOSED.append(word.strip())
        if number>=256:
            break
    geneate_header_file()

def geneate_header_file() -> None:
    header_file_fp=open('../src/dictionary.h','w')
    header_file_fp.write(F_HEADER)
    for word in WORDS_CHOOSED:
        header_file_fp.write('{"'+word+'"},\n')
    header_file_fp.seek(header_file_fp.tell()-2)
    header_file_fp.write(F_TAIL)
    header_file_fp.flush()
    header_file_fp.close()

main()