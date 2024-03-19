import re

from ntdshs_utils.utils import *

class Parser:
    def __init__(self,file, glob, index):
        self.file = file
        self.nb_hashes = 0
        self.glob = glob
        self.index = index
        self.hash_index = 0
        self.user_index = 0
        self.threshold = 2 # repetition threshold

    
    def parse(self):
        # Parse first file
        with open(self.file,'r') as ntds:
            name1 = ntds.name
            
            # Regex smart parse to find hash and user indexes
            self.findIndexes()
            
            for l in ntds:
                user = l.split(':')[self.user_index].replace('\n','')
                if user.startswith('[*]') or user.startswith('Impacket') or user == '\n':
                    continue

                self.nb_hashes+=1
                h = l.split(':')[self.hash_index].replace('\n','')
                try:
                    self.glob[h][self.index] +=1
                    self.glob[h][2].append(user)
                except KeyError:
                    if self.index:
                        self.glob[h] = [0,1, [user]]
                    else:
                        self.glob[h] = [1,0, [user]]
                except IndexError:
                    print("Unexpected index error, contact dev pls")
        nt1 = [(k,v) for k, v in sorted(self.glob.items(), key=lambda item: item[1][0])]
        self.nt1 = nt1
        # return nt1

    def findIndexes(self):
        adm_reg = re.compile("(Administrator)?\:?(500)?\:?(aad3b435b51404eeaad3b435b51404ee)?\:?([0-9A-Fa-f]{32})")
        guest_reg = re.compile("(Guest)?\:?(501)?\:?(aad3b435b51404eeaad3b435b51404ee)?\:?([0-9A-Fa-f]{32})")
        krbtgt_reg = re.compile("(krbtgt)?\:?(502)?\:?(aad3b435b51404eeaad3b435b51404ee)?\:?([0-9A-Fa-f]{32})")

        with open(self.file,'r') as ntds:
            for l in ntds:
                adm = adm_reg.match(l)
                guest = guest_reg.match(l)
                krbtgt = krbtgt_reg.match(l)
                
                split = [st.replace('\n','') for st in l.split(':')]
                if adm:
                    self.user_index = split.index(adm[1])
                    self.hash_index = split.index(adm[4])
                    return
                elif guest_reg.match(l):
                    self.user_index = split.index(guest[1])
                    self.hash_index = split.index(guest[4])
                    return
                elif krbtgt_reg.match(l):
                    self.user_index = split.index(krbtgt[1])
                    self.hash_index = split.index(krbtgt[4])
                    return
        
        # If no match, assume User:NT
        self.user_index = 0
        self.hash_index = 1
        return


    def topHashes(self):
        # Top Hashes
        printOK(f'{self.nb_hashes} hashes in {self.file}')

        # printHEADER(f"Top hashes from {self.file} (> {self.threshold} times)")
        for i in self.nt1[::-1]:
            if i[1][0] >= self.threshold:
                printINFO(f'{i[0]} found {i[1][0]} times')
