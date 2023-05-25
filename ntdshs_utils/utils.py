################ Pretty print
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
