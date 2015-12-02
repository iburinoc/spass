spass
=====

A command-line password database built on the ibcrypt library.

Note: There is an insecurity in this program if the attacker has read/write
access to your computer.  It does not compromise the passwords, but it may
compromise the quantity and names of the passwords.  For an attacker without
write access this is not an issue.

Dependencies
------------
- ibcrypt
- libibur
