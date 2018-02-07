package com.microsoft;

import java.io.IOException;
import java.security.cert.CertificateException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.CloudException;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.requests.SetSecretRequest;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.keyvault.Vault;
import com.microsoft.azure.management.resources.fluentcore.arm.Region;
import com.microsoft.azure.management.resources.fluentcore.utils.SdkContext;
import com.microsoft.rest.LogLevel;

public class Main {
	
	private static Region VAULT_REGION = Region.US_WEST;
	
	private static Azure azure;

	public static void main(String[] args) throws CloudException, IOException, CertificateException, OperatorCreationException, PKCSException, InterruptedException {
		
		//Asserting that required environment variables are set.
		assert(System.getenv("AZURE_CLIENT_ID") != null);
		assert(System.getenv("AZURE_CLIENT_SECRET") != null);
		assert(System.getenv("AZURE_TENANT_ID") != null);
		authenticateToAzure();
		
		//demoing ADAL Auth
		KeyVaultClient kvClientADALAuth = KeyVaultADALAuthenticator.getAuthenticatedClient();
		
		System.out.println("Creating secret");
		Vault vaultADAL = createKeyVault();
		SecretBundle secretBundle = kvClientADALAuth.setSecret(new SetSecretRequest.Builder("https://" + vaultADAL.vaultUri(), "auth-sample-secret", "client is authenticated to the vault").build());
		System.out.println(secretBundle);
		
		System.out.println("Getting Secret");
		secretBundle = kvClientADALAuth.getSecret("https://" + vaultADAL.vaultUri(), "auth-sample-secret");
		System.out.println(secretBundle);
		
		//demoing Certificate auth
		KeyVaultClient kvClientCertAuth = KeyVaultCertificateAuthenticator.getAuthenticatedClient(System.getenv("CERTIFICATE_PATH"), System.getenv("CERTIFICATE_PASSWORD"));
		
		System.out.println("Creating secret");
		Vault vaultCert = createKeyVault();
		
		SecretBundle otherSecretBundle = kvClientCertAuth.setSecret(new SetSecretRequest.Builder("https://" + vaultCert.vaultUri(), "auth-other-sample-secret", "client is authenticated to the vault").build());
		System.out.println(otherSecretBundle);
		
		System.out.println("Getting Secret");
		otherSecretBundle = kvClientCertAuth.getSecret("https://" + vaultCert.vaultUri(), "auth-other-sample-secret");
		System.out.println(otherSecretBundle);
	}
	
	private static Vault createKeyVault() throws InterruptedException {
		final String vaultName = SdkContext.randomResourceName("vault", 20);
		final String rgName = SdkContext.randomResourceName("rg", 24);
		
		System.out.println("Creating a new vault...");
		Vault vault = azure.vaults().define(vaultName)
				.withRegion(VAULT_REGION)
				.withNewResourceGroup(rgName)
				.defineAccessPolicy()
					.forServicePrincipal(System.getenv("AZURE_CLIENT_ID"))
					.allowKeyAllPermissions()
					.allowSecretAllPermissions()
					.attach()
				.create();
		System.out.println(vault.vaultUri());
		System.out.println(vault.name());
		
		Thread.sleep(20000);
		return vault;
	}
	
	private static void authenticateToAzure() throws CloudException, IOException {
		//Authentication for general Azure service
		ApplicationTokenCredentials credentials = new ApplicationTokenCredentials(
				System.getenv("AZURE_CLIENT_ID"), System.getenv("AZURE_TENANT_ID"), System.getenv("AZURE_CLIENT_SECRET"), AzureEnvironment.AZURE);
				
		azure = Azure.configure()
                .withLogLevel(LogLevel.BASIC)
                .authenticate(credentials)
                .withDefaultSubscription();
	}
	
}
