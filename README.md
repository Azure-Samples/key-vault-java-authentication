---
services: key-vault
platforms: java
author: tiffanyachen
---

# Authentication samples for Azure Key Vault using the Azure Java SDK

This sample repo contains sample code demonstrating common mechanisms for authenticating to an Auzure Key Vault vault.

## Samples in this repo
* KeyVaultADALAuthenticator -- authenticates to an Azure Key Vault by providing a callback to authenticate using [ADAL](https://github.com/AzureAD/azure-activedirectory-library-for-java).
* KeyVaultCertificateAuthenticator -- authenticates to an Azure Key Vault through a [service principal with a self signed certificate](https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli?toc=%2Fazure%2Fazure-resource-manager%2Ftoc.json&view=azure-cli-latest#create-a-service-principal-with-a-self-signed-certificate). This takes in a pem file with the certificate and private key.


## Running the samples
1. If not installed, install [Java](https://www.java.com/en/download/help/download_options.xml).

2. Clone the repository.
```
git clone https://github.com/Azure-Samples/key-vault-java-authentication.git
```
3. Create an Azure service principal, using
[Azure CLI](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/),
[PowerShell](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/)
or [Azure Portal](http://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/).
Note that if you wish to authenticate with the certificate authenticator the certificate should be saved locally.

4. Export these environment variables into your current shell or IDE.
```
    AZURE_TENANT_ID={your tenant id}
    AZURE_CLIENT_ID={your service principal AppID}
    AZURE_CLIENT_SECRET={your application key}
    CERTIFICATE_PATH={absolute path to locally stored certificate}
    CERTIFICATE_PASSWORD={password for locally stored certificate}
```

AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must be set for general Azure authentication.

For ADAL authentication, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET must be set.

For certificate authentication, AZURE_CLIENT_ID, CERTIFICATE_PATH and CERTIFICATE_PASSWORD must be set.

5. Run main.java for a sample run through. This project uses maven so you can do so either through an IDE or on the command line.


## More information

* [What is Key Vault?](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis)
* [Get started with Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started)
* [Azure Key Vault General Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
* [Azure Key Vault REST API Reference](https://docs.microsoft.com/en-us/rest/api/keyvault/)
* [Azure SDK for Java Documentation](https://docs.microsoft.com/en-us/java/api/overview/azure/keyvault)
* [Azure Active Directory Documenation](https://docs.microsoft.com/en-us/azure/active-directory/)
