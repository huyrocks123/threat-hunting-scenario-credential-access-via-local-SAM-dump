# Threat Event (Credential Access via Local SAM Dump)
**User Dumps SAM, SYSTEM, and SECURITY Registry Hives for Offline Password Cracking**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Open an elevated command prompt (run as administrator).
2. Use built-in reg save command to dump sensitive hives:
```kql
reg save HKLM\SAM C:\Users\Public\SAM.save
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM.save
reg save HKLM\SECURITY C:\Users\Public\SECURITY.save
```
3. Compress all dumped files into hashes.zip:
```kql
powershell Compress-Archive -Path C:\Users\Public\SAM.save, C:\Users\Public\SYSTEM.save, C:\Users\Public\SECURITY.save -DestinationPath C:\Users\Public\hashes.zip
```
5. Delete original .save files to reduce footprint.
6. Leave hashes.zip in the folder for later retrieval or exfiltration.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table |
| **Purpose**| 	Detects usage of reg.exe and powershell.exe with suspicious command lines. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/devicefileevents-table |
| **Purpose**| 	Detects the creation of sensitive registry hives and compressed archive. |

---

## Related Queries:
```kql
// Detect reg.exe being used to dump SAM/SYSTEM/SECURITY
DeviceProcessEvents
| where FileName =~ "reg.exe"
| where ProcessCommandLine has_any ("HKLM\\SAM", "HKLM\\SYSTEM", "HKLM\\SECURITY")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect creation of dumped hive files
DeviceFileEvents
| where FileName in~ ("SAM.save", "SYSTEM.save", "SECURITY.save")
| project Timestamp, DeviceName, FolderPath, ActionType, InitiatingProcessAccountName

// Detect creation of suspicious archive
DeviceFileEvents
| where FileName =~ "hashes.zip"
| project Timestamp, DeviceName, FolderPath, ActionType, InitiatingProcessAccountName

// Check if original files were deleted
DeviceFileEvents
| where FileName has_any("SAM.save", "SYSTEM.save", "SECURITY.save")
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, RequestAccountName
```

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 11, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 11, 2025  | Huy Tang  
