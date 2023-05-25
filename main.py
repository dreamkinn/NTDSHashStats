#!/usr/bin/python3
import argparse
from ntdshs_utils.utils import *
from ntdshs_utils.parser import *


# Args
parser = argparse.ArgumentParser(description='Stats on similar NT hashes between domains')
parser.add_argument('ntds', type=str, help='NTDS domain 1 (username:id:lm:nt:::)')
parser.add_argument('--compare', '-c', type=str, help='NTDS domain 2')
parser.add_argument('-da', type=str, help='Domain Admin list')
args = parser.parse_args()
args = vars(args)

glob = {}

parse = Parser(args["ntds"],glob,0)
parse.parse()
parse.topHashes()
a = parse.nb_hashes

if args["compare"] is not None:
    parse2 = Parser(args["compare"],glob,1)
    parse2.parse()
    parse2.topHashes()
    b = parse2.nb_hashes


name1 = args["ntds"]
name2 = args["compare"]


if args["compare"] is None:
    exit(0)

# Common hashes
printHEADER("Finding common hashes")
common = {k:v for k,v in glob.items() if v[0]*v[1] > 0}

printOK(f'There are {len(common)} common hashes in the two NTDS databases')
total = 0
for i in common.keys():
    number1 = common[i][0]
    number2 = common[i][1]
    users = common[i][2]
    total += int(common[i][0]) + int(common[i][1])

    if len(common[i][2]) > 3:
        printINFO(f'{i} || {name1} : {number1} || {name2} : {number1} || [{users[0]},...,{users[-1]}]')
    else:
        printINFO(f'{i} || {name1} : {number1} || {name2} : {number2} || {users}')


printFAIL(f"Number of impacted accounts : {total}")


dadict = {}

try:
    if not args["da"]:
        printHEADER('You can pass a list of domain admins with : -da da_list (will match ignoring case!)')
        exit(0)

    with open(args["da"],'r') as dalist:
        for da in dalist:
            for h in common.keys():
                for username in common[h][2]:
                    if da.replace('\n','').lower() in username.lower(): # case insensitive
                        replaced = da.replace('\n','').lower() 
                        printFAIL(f'Potential DA password reuse : {bcolors.ENDC}{bcolors.OKGREEN}"{username}"{bcolors.ENDC} contains {bcolors.OKGREEN}"{replaced}"{bcolors.ENDC} from {args["da"]}, matching as DA')
                        try:
                            if h not in dadict[da.replace('\n','').lower()]:
                                dadict[da.replace('\n','').lower()].append(h)
                        except:
                            dadict[da.replace('\n','').lower()] = [h]

    printFAIL(f'{len(dadict.keys())} potential DA accounts with password reuse')

    for da in dadict.keys():
        printFAIL(f'Password reuse for DA : {da} : {dadict[da]}')
except FileNotFoundError:
    printFAIL(f'Could not open file {args["da"]}')
                    
