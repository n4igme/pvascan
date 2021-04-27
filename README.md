# pvascan
Python vulnerability scanner tool which using [Exploit-DB][edb] files.csv as vulnerability database reference. 
This is just a Proof of Concept tool that automation Vulnerability Assessment while scanning port of Operating System.

####Some factors that influence result of pvascan :
* Application's banner of [nmap][nmp] result scan.
* Randomly named application at description [files.csv][csv] of Exploit-DB.

####Screenshot
![alt text][sc1]

[edb]: https://www.exploit-db.com/
[nmp]: https://nmap.org/
[csv]: https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv
[sc1]: https://lh3.googleusercontent.com/-XI1h_Hz0pxE/Vk6aeU-TtZI/AAAAAAAAB_o/-vxsiDiNa3k/h409/pvascan.png "pvascan"
