# Aid in decommissionning a Certification Authority

This script is an aid in decommissioning a Certification Authority (CA).

It allows to save the CA Root Certificate and Key to a location of your choice, including a full backup of the CA databse.

All active certificates are revoked and a Certificate Revocation List (CRL) is published in Active Directory with an expiration date later than the expiration date of any certificate published by this CA.

# Dependencies

You must install PSPKI (also available on the PowerShell Gallery).

# Caution

In theory, this script can be executed against a remote CA. This has not been tested and saving the CA Root Certificate is restricted to the local machine.

This script is mainly used to decommission the CA installed by default on Microsoft Small Business Servers and Essential Servers

### Usage:

Run this script with administrator privileges.

Note: the PSPKI package seems to issue a number of messages on non-US editions of Windows Server.

On entry, the script will display the status of the CA and request a password used to export the CA key and a copy of the CA database.

Explicit confirmation is required to decommission the CA:

````
Please wait...

Name                      Status Childs
----                      ------ ------
pcevolution-CHATTERBOX-CA  Error {pcevolution-CHATTERBOX-CA}


Enter password for C:\Users\Administrator\Desktop\CertServer\Export-pcevolution-CHATTERBOX-CA.pfx: ************
Confirm password: ************

Destination : C:\Users\Administrator\Desktop\CertServer\Export-pcevolution-CHATTERBOX-CA.pfx ».

AVERTISSEMENT : A backup of the CA was also stored in the destination folder using the same password.

Caution: This script irreversibly revokes everything issued by this Certification Authority.
         This includes Disaster Recovery Agents and other critical roles.
         Upon successfull execution, local operations are still enabled on the CA: if need be,
         you can rerun this script locally.

Please confirm retirement of pcevolution-CHATTERBOX-CA [Enter IDO, anything else exits]: IDO

````

Once decommission is confirmed, CA operations are frozen and the CA is restarted. All certificates are revoked and a lifetime for the last Certificate Revocation List is computed as the furthest expiration date of these certificates plus 2 days. The CRL is then published.

Finally, local CA operations are thawed, in case something needs to be restored ;-)

The administrator can then proceed to remove the CA role. Typically in these Small Business/Essentials servers, the target is also a domain controller: this process is not covered here.
