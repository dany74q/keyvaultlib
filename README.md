# keyvaultlib
A KeyVault client wrapper that helps transition between using ADAL (Active Directory Authentication Libraries) and MSI (Managed Service Identity) as a token provider.
Moreover, this library provides support for User-Assigned identities (MSI) and non-public (e.g. Government) Azure clouds.

# What is KeyVault ?
Key Vault is an Azure managed cloud service that allows you to securely store secrets in a variety of forms:
- Credentials
- Connection Strings
- Private Keys and Certificates in various formats
- ...

It provides auditing and integrates easily with AAD (Azure-Active-Directory) for user or application based authorization.
More about KeyVault can be found in the following link:
https://docs.microsoft.com/en-us/azure/key-vault/key-vault-overview

# What is ADAL (Active Directory Authentication Libraries) ?
ADAL are a set of libraries provided by the AAD (Azure-Active-Directory) team in a variety of programming languages
that allows one to easily interact with their cloud active directory.
For example, the libraries could be used for authentication and authorization with Azure resources

More about ADAL can be found in the following link:
https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-authentication-libraries

# What is MSI (Managed-Service-Identity) ?
MSI was created to ease the authentication flow for Azure services, while providing a per-VM granularity of control.
Once MSI is enabled on your VM, your virtual machine will be assigned an application or user client ID, 
with which you could easily receive access tokens for Azure resources, which you may then authorize your VM to use.
It also saves the need to store your service principal information on disk, or worse, in your code base.

More about MSI can be found in the following link:
https://docs.microsoft.com/en-us/azure/active-directory/managed-service-identity/overview

# How to use this wrapper effectively ?
This KeyVault client was created for reducing the small code duplication involving the use of either MSI or ADAL / Service Principal Credentials.
A common use case being - having part of your code running on Azure VMs while another part running on your local machine or VM,
where MSI is not accessible.

# Example
First, install the library via:

$> pip install keyvaultlib

Next, import KeyVaultOAuthClient and choose your authentication strategy;

Currently supported: Using Service Principal credentials for ADAL or MSI

```python
from keyvaultlib.key_vault import KeyVaultOAuthClient

# MSI Example
client = KeyVaultOAuthClient(use_msi=True)
secret = client.get_secret_with_key_vault_name('my-key-vault', 'my-secret')

# MSI - User Assigned Identity example
client = KeyVaultOAuthClient(use_msi=True, client_id='my_user_assigned_client_id')
secret = client.get_secret_with_key_vault_name('my-key-vault', 'my-secret')

# ADAL / SPN Example
client = KeyVaultOAuthClient(
  client_id='my_user_or_app_client_id', 
  client_secret='my_user_or_app_client_secret', 
  tenant_id='my_AAD_tenant_id'
)
secret = client.get_secret_with_key_vault_name('my-key-vault', 'my-secret')

# Using government / non-public Azure Clouds Example:
client = KeyVaultOAuthClient(
  client_id='my_user_or_app_client_id', 
  client_secret='my_user_or_app_client_secret', 
  tenant_id='my_AAD_tenant_id',
  key_vault_resource_url='https://vault.usgovcloudapi.net'
)
secret = client.get_secret_with_key_vault_name('my-key-vault', 'my-secret')
```
