---
languages:
- java
page_type: sample
products:
- azure
- azure-key-vault
description: "This sample repo contains sample code demonstrating common mechanisms for authenticating to an Azure Key Vault."
---

# Authentication samples for Azure Key Vault using the Azure Java SDK

This sample repo contains sample code demonstrating common mechanisms for authenticating to an Azure Key Vault.

## This sample shows how to do the following operations of Key Vault with Key Vault SDK

* Create key vault

* Create a keyvault client using cert based authentication

* Create a secret inside the keyvault

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
3. Create an Azure service principal, using
[Azure CLI](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/),
[PowerShell](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/)
or [Azure Portal](http://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/).
Note that if you wish to authenticate with the certificate authenticator the certificate should be saved locally.

4. [Use an authentication file](https://github.com/Azure/azure-libraries-for-java/blob/master/AUTH.md#using-an-authentication-file) to authenticate to the Azure management plane.

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

For ADAL authentication, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET also must be set.

5. Run ```mvn clean compile exec:java``` for a sample run through.

## Use latest key vault SDK

The key vault SDK package  here is **com.microsoft.azure.azure-keyvault**, if you are using the [latest](https://search.maven.org/artifact/com.azure/azure-security-keyvault-secrets) version of the key vault SDK package, please reference to the following examples:

* [IdentityReadmeSamples.java](https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/keyvault/azure-security-keyvault-secrets/src/samples/java/com/azure/security/keyvault/secrets/IdentityReadmeSamples.java)- Examples to authenticate to key vault secret client

    * createClientCertificateCredential: Create a secret client using cert based authentication.
    * createDefaultAzureCredential: Create a secret client using DefaultAzureCredential.

* [HelloWorld.java](https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/keyvault/azure-security-keyvault-secrets/src/samples/java/com/azure/security/keyvault/secrets/HelloWorld.java)  - Examples for common key vault tasks:

    * Create a secret inside the keyvault
    * Get the secret

## More information

* [What is Key Vault?](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis)
* [Get started with Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started)
* [Azure Key Vault General Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
* [Azure Key Vault REST API Reference](https://docs.microsoft.com/en-us/rest/api/keyvault/)
* [Azure SDK for Java Documentation](https://docs.microsoft.com/en-us/java/api/overview/azure/keyvault)
* [Azure Active Directory Documenation](https://docs.microsoft.com/en-us/azure/active-directory/)
