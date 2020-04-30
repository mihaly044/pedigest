# pedigest
Helper functions for calculating the authenticode digest for a portable executable file.

This piece of code was originally meant to run in kernel mode but it works just as well in userland too. 

### Here's what you need to make this work in usermode
Link against bcrypt.lib instead of ksecdd.lib and use malloc/free instead of ExAllocatePoolWithTag/ExFreePool.

### Sample usage
  You need to map the PE image into system memory first. Either use ZwReadFile or  ZwCreateSection / MmMapViewInSystemSpace.

    UINT32 digestIdentifier;
    ULONG digestSize;
    ULONG securityDirSize;
    PUCHAR digest = NULL;
    LPWIN_CERTIFICATE cert = NULL;
    
    NTSTATUS status = CalculatePeDigest(
      baseAddrOfView, 
      (ULONG)viewSize,
      &digestIdentifier,
      &digestSize,
      (PVOID*)&digest,
      &cert,
      &securityDirSize
    );
  
The CalculatePeDigest function only accepts properly formatted PE/COFF files.
Don't forget to check for the returned status before using the output.
If the out cert is still null it means that the PE did not contain an embedded signature and you need to call CiVerifyHashInCatalog to check if the file has been signed in a catalog file.

### Disclaimer
I have used a rather primitive approach of finding out the correct message digest algorithm for a given PE image: pattern matching. There are certainly more elegant and better ways of doing it. I  discourage using this kind of approach in production code.
