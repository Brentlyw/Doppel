# Doppel
*An Advanced, Evasive, Persistent, Shellcode Loader and Executor for Windows.*

Doppel performs a wide variety of evasive maneuvers.


# Introductory

Döppel is a program that was developed sporadically over two weeks, so please understand it may not be perfect. It is developed to return -1 and exit if any errors occur in it’s flow, so if this happens then either something went wrong, or it detected something it doesn’t want to run on. Please enjoy reversing this program, and I hope some of the parts I worked hard on might make you smile.

# A Disclaimer

I made this program as a PoC (Proof of Concept) for a small competition. In no way is this program, or the payload it runs meant for harm or use on non-virtual machines. Please be responsible with the payload, and give it due respect as if it were a wild sample. Please note that this program does not cause ANY harm to the system it runs on, it purely allows for remote control via a C2 server. Please use this example for educational purposes, and enjoy!

# Important Features

I wanted Döppel to be different, so I included some non-standard things within it’s execution flow.

- Runs 8 individual virtual machine checks, querying mouse info, hardware specs, and recent activity.
- Is able to unhook ntdll.dll, and also patch ETW logging.
- Enables persistence in a non-standard fashion, using a debugger global flag attached to wuauclt.exe
- Dynamically resolves several core calls from Kernel32.dll to avoid detection.
- Decrypts the shellcode payload (XOR) ‘just in time’ within a loop, decrypting and injecting 10 chunks total to explorer.exe
- Sets the remote thread’s context to be within the MEM_IMAGE flag containing region to evade detection (For example, evades ‘get-injectedthreads.ps1 by Lee Christensen)
- Utilizes RC4 encrypted TCP connection to the stager server, to retrieve the main payload.
- Main payload communicates using reverse-HTTPs to the C2 server.
- Utilizes unique obfuscation patterns + packing to evade  RE, but probably not static analysis.

*If you like this, check out my UPXPatcher repo, which was made specifically for this PoC!*
