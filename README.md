---
languages:
- java
page_type: sample
products:
- azure
- azure-key-vault
description: "This sample repo contains sample code demonstrating common mechanisms for authenticating to an Azure Key Vault."
---

> **Warning**
> 
> **THIS DOCUMENT IS OUTDATED AND HAS BEEN DEPRECATED**.
> 
> For updated samples on how to authenticate with your Key Vault application, please refer to [this document](https://learn.microsoft.com/java/api/overview/azure/security-keyvault-keys-readme?view=azure-java-stable#authenticate-the-client). For a general overview about the Azure Identity library, see [here](https://learn.microsoft.com/java/api/overview/azure/identity-readme?view=azure-java-stable). You can also find samples on how to use most types of credentials for authentication [here](https://github.com/Azure-Samples/key-vault-java-authentication).

# Authentication samples for Azure Key Vault using the Azure Java SDK

This sample repo contains sample code demonstrating common mechanisms for authenticating to an Azure Key Vault.

## This sample shows how to do the following operations of Key Vault with Key Vault SDK

* Create Key Vault

* Create a Key Vault client using certificate based authentication

* Create a secret inside the Key Vault

* Get the secret

## Samples in this repo
* KeyVaultCertificateAuthenticator -- authenticates to an Azure Key Vault through a [service principal with a self signed certificate](https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli?toc=%2Fazure%2Fazure-resource-manager%2Ftoc.json&view=azure-cli-latest#create-a-service-principal-with-a-self-signed-certificate). This takes in a pem file with the certificate and private key. This is the recommended way to authenticate to Key Vault.
* KeyVaultADALAuthenticator -- authenticates to an Azure Key Vault by providing a callback to authenticate using [ADAL](https://github.com/AzureAD/azure-activedirectory-library-for-java).

## Prerequisites
- Java 1.7+
- An Azure Service Principal, through [Azure CLI](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/),
[PowerShell](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/)
or [Azure Portal](http://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/).
- A self signed certificate, uploaded to your service principal through Azure Portal or Powershell.

## Running the samples
1. If not installed, install [Java](https://www.java.com/en/download/help/download_options.xml).

2. Clone the repository.
```bash
git clone https://github.com/Azure-Samples/key-vault-java-authentication.git
```
3. Create an Azure service principal with a PEM certificate and an authentication file, using
[Azure CLI](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/):

```bash
   az ad sp create-for-rbac --name keyvaultsample  --create-cert keyvaultsamplecert.pem --sdk-auth > auth.file
```

4. Add these variables to pom.xml for a demo of certificate authentication. Note that CERTIFICATE_PASSWORD is optional depending on whether or not your .pem file requires a certificate.
```xml
    <systemProperties>
        <systemProperty>
                <key>AZURE_TENANT_ID</key>
                <value>{AZURE_TENANT_ID}</value>
        </systemProperty>
        <systemProperty>
                <key>AZURE_CLIENT_ID</key>
                <value>{AZURE_CLIENT_ID}</value>
        </systemProperty>
        <systemProperty>
                <key>AZURE_AUTH_LOCATION</key>
                <value>{AZURE_AUTH_LOCATION}</value>
        </systemProperty>
        <systemProperty>
                <key>CERTIFICATE_PATH</key>
                <value>{CERTIFICATE_PATH}</value>
        </systemProperty>
        <systemProperty>
                <key>CERTIFICATE_PASSWORD</key>
                <value>{CERTIFICATE_PASSWORD}</value>
        </systemProperty>
<systemProperties>
```

`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `CERTIFICATE_PATH` values may be found inside the newly-created authentication file (i.e. `auth.file` from step 3 above). `AZURE_AUTH_LOCATION` value is the full path of that authentication file.

For ADAL authentication, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET also must be set.

5. Run ```mvn clean compile exec:java``` for a sample run through.

## Use latest Key Vault SDK

The Key Vault secrets SDK here is **com.azure.azure-security-keyvault-secrets**, if you are using the [latest](https://search.maven.org/artifact/com.azure/azure-security-keyvault-secrets) version of the Key Vault SDK package, please refer to the following examples:

* [IdentityReadmeSamples.java](https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/keyvault/azure-security-keyvault-secrets/src/samples/java/com/azure/security/keyvault/secrets/IdentityReadmeSamples.java) shows multiple ways to authenticate the Key Vault client via DefaultAzureCredential, device code, client secret or certificate in addition to others.

* [HelloWorld.java](https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/keyvault/azure-security-keyvault-secrets/src/samples/java/com/azure/security/keyvault/secrets/HelloWorld.java)  - Examples for common Key Vault tasks:

    * Create a secret inside the Key Vault
    * Get the secret

## More information

* [What is Key Vault?](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis)
* [Get started with Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started)
* [Azure Key Vault General Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
* [Azure Key Vault REST API Reference](https://docs.microsoft.com/en-us/rest/api/keyvault/)
* [Azure SDK for Java Documentation](https://docs.microsoft.com/en-us/java/api/overview/azure/keyvault)
* [Azure Active Directory Documenation](https://docs.microsoft.com/en-us/azure/active-directory/)
