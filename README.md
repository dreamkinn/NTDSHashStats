# Password reuse statistics on NTDS databases
What the tool does :
- takes two ntds database extracts (crackmapexec, secretsdump...)
- counts hash reuse, and common hashes between databases

- optionally : takes as input a list of "Domain Admin" users to find password reuse among privileged users 


Why the tool does that :
- You just finished your multi-domain internal pentest and you want stats on admin password reuse

## Usage 
```
py compare_domain_hashes.py ntds1 ntds2 [-da domain_admin_users_list]
```


## TODO
- exhaustive output of impacted users
- csv output of users 
