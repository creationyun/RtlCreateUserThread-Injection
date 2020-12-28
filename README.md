# RtlCreateUserThread-Injection
Process Shellcode Injection using RtlCreateUserThread.

## Usage

After compiling in Visual Studio (x86 Release recommended),

```
RtlCreateUserThread-Injection.exe <ProcessID>
```

Example: `RtlCreateUserThread-Injection.exe 1234`

## Caution

+ It can ONLY inject **32-bit processes**.
+ It is NOT malware (just executes calc.exe) but **can be detected** as.

