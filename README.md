# Update-AllUsersQA
Update-AllUsersQA is a PowerShell script used to change or disable the security questions and answers for local users in a Windows 10 machine.</br>
It is designed to allow admins to control the security questions in the environment and minimize the risk that arises from them.
The concept is covered in our BlackHat 2018 talk [When Everyone's Dog is Named Fluffy: Abusing the Brand New Security Questions in Windows 10 to Gain Domain-Wide Persistence](https://www.blackhat.com/eu-18/briefings/schedule/index.html#when-everyone39s-dog-is-named-fluffy-abusing-the-brand-new-security-questions-in-windows-10-to-gain-domain-wide-persistence-12863)

## How to use
Disable security questions on the machine (user who tries to reset will recieve an error alert):
```
Update-AllUsersQA
```
Set all answers to the same value "SecretAnswer" (user will see a message saying that the feature has been disabled, but it will infact remain active):
```
Usage: Update-AllUsersQA -answer SecretAnswer 
```

## Example
### Execution of the code (with "-answer" parameter provided):
![alt tag](https://i.ibb.co/b3q3S8W/Urty.png "UpdateAllUsersQA Example")
### Screen user receives after the answers were set to a single value (with "-answer" parameter provided):
![alt tag](https://i.ibb.co/s1w1VcG/locked.png "Answers set to a single value")
### Screen user receives after the questions were disabled (no "-answer" parameter provided):
![alt tag](https://i.ibb.co/HxbzLdw/disabled.png "Disabled security questions")




## Author    
Magal Baz

## License
This project is licensed under the GNU General Public license

## Credits
* Nikhil "SamratAshok" Mittal

* [Illusive Networks](https://www.illusivenetworks.com/) Research team members:
  * Dolev Ben Shushan
  * Tom Kahana  
  * Hadar Yudovich
  * Tom Sela

All attempts were made to give credit where credit is due. If you find that we used your code here without giving proper credit, please contact us at mbaz@illusivenetworks.com