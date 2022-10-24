# PowerKnocka
A light weight powershell utility to dynamically create user accounts based on failed logons

## Concept
On a great and ospicious day [@evanjd711](https://github.com/evanjd711) and I were thinking about how to create the ultiamte method of limitless persistence. Besides literally breaking windows authentication there isn't really a native way to get this type of unlimited access. So why not make it :sunglasses:. Essentially we watch for failed logon attempts, parse the username, and either reset the password to that account or create it with a known password. TLDR; port knocking but for credentials.

## Methods
### Task Scheduler
Creates a scheduled task with a trigger on Event ID 4625 that parses the latest event for the username and creates such an account or resets the password.
### WMI Event Subscription
