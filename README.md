# LsassHijackingViaReg

</br>

Loading a DLL into LSASS at boot, providing persistence.


### How?

</br>

1. **Lsass.exe is found to be reading two registry keys at startup to load DLLs from the `System32` directory. These keys are:**


![image](https://github.com/user-attachments/assets/458e2d83-e1de-459a-82a6-29075e306d02)

* *Extension* under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\Interfaces\1001` to read `lsasrv.dll`.

![image](https://github.com/user-attachments/assets/638a213d-8671-4086-a17a-e491bd0ce5ae)

* *Extension* under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\Interfaces\1002` to read `dpapisrv.dll`.

![image](https://github.com/user-attachments/assets/1a2bcfec-7702-4e13-9efa-143cffacac76)

</br>


2. **We constructed a program that elevates to TrustedInstaller to edit one of these registry keys, replacing the original DLL name with ours.**


![IMG1](https://github.com/user-attachments/assets/a5fcdc5a-45f6-4fa1-98c6-5b9079cdd652)


> [!NOTE]
> * The same program disables PPL to load an unsigned DLL into LSASS. Otherwise, we will get stuck in a boot loop, because Lsass will crash before startup (due to having an unsigned DLL loaded). One can get around this by loading a signed but vulnerable DLL and exploiting it later (BYOVDLL - Bring Your Own Vulnerable DLL).
> * We are replacing the `dpapisrv.dll` DLL instead of the `lsasrv.dll` DLL, because the latter DLL has far more exported variables/functions, which make proxying such DLL less stable (for comparison, `dpapisrv.dll` contains 2 exported functions only).

</br>

3. **After the next system boot, our DLL (`Dummy.dll`) will be loaded into the Lsass.exe.**

![IMG2](https://github.com/user-attachments/assets/a32be11a-82e8-498c-8ae3-14e434431026)

</br>



### Quick Links

[Maldev Academy Home](https://maldevacademy.com)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus)

[Offensive Phishing Operations](https://maldevacademy.com/phishing-course)

[Maldev Database](https://search.maldevacademy.com/updates)
