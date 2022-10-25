# PowerKnocka
A lightweight PowerShell utility to dynamically create user accounts based on failed logons

## Concept
On a great and auspicious day [@evanjd711](https://github.com/evanjd711) and I were thinking about how to create the ultimate method of limitless persistence. Besides literally breaking windows authentication there isn't really a native way to get this type of unlimited access. So why not make it 😎. Essentially we watch for failed logon attempts, parse the username, and either reset the password to that account or create it with a known password. TLDR; port knocking but for credentials.

## Methods
### Task Scheduler
Creates a scheduled task with a trigger on Event ID 4625 that parses the latest event for the username and creates such an account or resets the password.
### WMI Event Subscription
Same idea as the task scheduler method, except instead of using tasks it creates a WMI Subscription.

## OPSEC
A disaster 💀. This is meant to be something that is effective when aided by the element of surprise. However, there are plans to increase evasion in terms of better disguising the event logs.
