---
title: Taking a look at the Leprechaun Loader
published: 2025-10-20
description: 'Diving into leprechaun loader, performing static and dynamic analysis of the malware.'
image: ''
tags: ['malware-analysis', 'reversing']
category: 'malware-analysis'
draft: false
---

- Introduction
- Metadata
- Overview
- Static Analysis
- Dynamic Analysis
- Final Words

---
## Introduction

This malware is a loader called `LeprechaunHvnc`. That downloads the implant from the c2 server onto the target machine. Initially discovered by [Kseniia N](https://x.com/naumovax/status/1775185431237206209).

## Metadata

**SHA256:** `1d0753beaabc660960bb5297f43eae38128647c2a23b02b2550646d58aff8797`
Sample Link: [baazar.abuse.ch](https://bazaar.abuse.ch/sample/1d0753beaabc660960bb5297f43eae38128647c2a23b02b2550646d58aff8797#)

## Overview

!--- summary of the analysis here --–!

## Static Analysis

### Inspecting in PE Studio
File properties

![alt text](./images/leprechaun/Pasted%20image%2020251018115948.png)

Looking at the strings in PE studio we find some important indicators that this binary is an implant and part of a c2.

![alt text](./images/leprechaun/Pasted%20image%2020251018120102.png)

Additionally we look at the libraries being used in the implant. Pretty generic stuff WININET for creating conenctions between the compromised machine and the c2 server.

![alt text](./images/leprechaun/Pasted%20image%2020251018120154.png)

### Analyzing using IDA

![alt text](./images/leprechaun/Pasted%20image%2020251018122033.png)

We have a few functions and a huge graph starting from the start function.

Looking through the graph view, initially we find use of Urlmon.dll file, going a little further we find the address of the c2 server being used:

![alt text](./images/leprechaun/Pasted%20image%2020251018170702.png)

Looking further we find that there are 2 operations being performed depending on the condition whether the implant is installed or not.

![alt text](./images/leprechaun/Pasted%20image%2020251019121957.png)

Before that we see a function called `sub_401640` that simply checks whether the subkey Software\\LeprechaunHvnc is present in the location HKEY_CURRENT_USER, basically it checks if the implant is present on the target or not.

![alt text](./images/leprechaun/Pasted%20image%2020251019122542.png)
#### Function 1 - `sub_4012A0` 

The first thing we find is, the malware is utilising the GetUserName function to enumerate whether the current active user is an administrator or a normal user.

![alt text](./images/leprechaun/Pasted%20image%2020251019122038.png)

Next we see that another function `sub_401680` is called, opening this function we find that it is being used to determine the os version.

![alt text](./images/leprechaun/Pasted%20image%2020251019122203.png)

![alt text](./images/leprechaun/Pasted%20image%2020251019122252.png)

After the user and the windows version are enumerated the string length function is used to store the value of both in variable v6 (for user) and the windows version string length is added to the v6 variable value and stored in v7. And the last v8 variable stores the string length of the value returned from the `GetUserNameW` function we saw initially and adds it us with the value of variable v7 along with some more space.

![alt text](./images/leprechaun/Pasted%20image%2020251019123457.png)

The next part of the function establishes a connection with the c2 and downloads the implant using the HttpOpenRequestW api function and sends a GET request.

![alt text](./images/leprechaun/Pasted%20image%2020251019203547.png)

Moving on to the next part of the function, it creates a registry key named “Software\LeprechaunHvnc” and sets value named “ID” in that key.

![alt text](./images/leprechaun/Pasted%20image%2020251019203803.png)

The last part of the current function checks if the value of the lpString2 is “User” (which is determined from the initial checks this function performs). If the value is user, then the file generates a directory named `WindowsecurityUpdates` under the documents directory and copies the downloaded implant to the created directory within documents directory. It also creates a registry subkey named `windowsupdates`.

![alt text](./images/leprechaun/Pasted%20image%2020251019204504.png)

#### Function 2 - `sub_4011F0` 

Now we will take a look at the other function which is called when the registry key for the Leprechaun exists. This function checks if the value **ID** is present inside the registry key `Software\\LeprechaunHvnc`

![alt text](./images/leprechaun/Pasted%20image%2020251019205125.png)

Now moving back to the main (start) function going further from the registry key check functions we find that it is using the Internet API and sending a GET request to the c2 server which is the value stored inside the v11 variable.

![alt text](./images/leprechaun/Pasted%20image%2020251019210536.png)

Moving further we find a function `sub_4019D0` being called that downloads something from the c2 server.

![alt text](./images/leprechaun/Pasted%20image%2020251019211027.png)

Next we see the functionality of the malware which is responsible for fetching tasks from the c2 operator, replying with task status and performing certain tasks.

![alt text](./images/leprechaun/Pasted%20image%2020251019211858.png)

One part of function checks the activity status of the loader, whe it is started or stopped.

![alt text](./images/leprechaun/Pasted%20image%2020251019211934.png)

Looking at the last part of the loader we see that it creates a temporary directory called temp and prepares it to download a file from the specified URL and send the confirmation back to the c2 operator.

![alt text](./images/leprechaun/Pasted%20image%2020251019212458.png)

And the work of the loader is finished here after downloading the implant onto the target system.

## Dynamic Analysis
### Checking the HTTP traffic using Wireshark
We start up wireshark, make sure its listening on our network card and execute the leprechaun.exe file.

Filtering for http traffic in wireshark we find that the loader tries to send the os version and user details to the c2 operator and then further tries to receive commands but the c2 is shut down, so it keeps trying to reach out to the c2 continuously.

![alt text](./images/leprechaun/Pasted%20image%2020251019220043.png)

### Checking the registry records
Furthermore we check the registry editor and find that a registry key is created with the name LeprechaunHvnc with a value ID as we saw in our analysis using IDA above.

![alt text](./images/leprechaun/Pasted%20image%2020251019220924.png)