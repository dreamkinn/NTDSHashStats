#!/usr/bin/python3
import argparse


# repetition threshold
threshold = 5 


# pretty colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def printHEADER(str):
    print(f'{bcolors.HEADER}## {str}{bcolors.ENDC}')

def printOK(str):
    print(f'{bcolors.OKGREEN}[+] {str}{bcolors.ENDC}')

def printINFO(str):
    print(f'{bcolors.WARNING}{str}{bcolors.ENDC}')

def printFAIL(str):
    print(f'{bcolors.FAIL}[!] {str}{bcolors.ENDC}')

# args
parser = argparse.ArgumentParser(description='Stats on similar NT hashes between domains')

parser.add_argument('ntds1', type=str, help='NTDS domain 1 (username:id:lm:nt:::)')
parser.add_argument('ntds2', type=str, help='NTDS domain 2')
parser.add_argument('-da', type=str, help='Domain Admin list')
args = parser.parse_args()
args = vars(args)


glob = {}

# number of accounts
a = 0
b = 0

# Parse first file
with open(args["ntds1"],'r') as ntds:
    name1 = ntds.name
    for l in ntds:
        user = l.split(':')[0]
        if user.startswith('[*]') or user.startswith('Impacket') or user == '\n':
            continue

        a+=1
        h = l.split(':')[3]
        try:
            glob[h][0] +=1
            glob[h][2].append(user)
        except KeyError:
            glob[h] = [1,0,[user]]

# Parse second file
with open(args["ntds2"],'r') as ntds:
    name2 = ntds.name
    for l in ntds:
        user = l.split(':')[0]
        if user.startswith('[*]') or user.startswith('Impacket') or user == '\n':
            continue

        b+=1
        h = l.split(':')[3]
        try:
            glob[h][1] += 1
            glob[h][2].append(user)
        except KeyError:
            glob[h] = [0,1,[user]]


nt1 = [(k,v) for k, v in sorted(glob.items(), key=lambda item: item[1][0])]
nt2 = [(k,v) for k, v in sorted(glob.items(), key=lambda item: item[1][1])]


# Top Hashes
printOK(f'{a} hashes in {name1}')

printHEADER(f"Top hashes from {name1} (> {threshold} times)")
for i in nt1[::-1]:
    if i[1][0] >= threshold:
        printINFO(f'{i[0]} found {i[1][0]} times')


printOK(f'{b} hashes in {name2}')
printHEADER(f"Top hashes from {name2} (> {threshold} times)")
for i in nt2[::-1]:
    if i[1][1] >= threshold:
        printINFO(f'{i[0]} found {i[1][1]} times')

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
                    
