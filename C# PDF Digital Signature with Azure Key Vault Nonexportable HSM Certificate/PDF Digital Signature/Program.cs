using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using SignLib.Certificates;
using SignLib.Pdf;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PDF_Digital_Signature
{
    public class ExternalSignature : SignLib.Certificates.IExternalSignature
    {
        Uri _keyVaultUrl;
        string _vaultCertificateName;
        Uri _keyVaultCertificatePrivateKeyUrl;
        public X509Certificate2 RemoteSignatureCertificate { get; }

        public ExternalSignature(Uri keyVaultUrl, string vaultCertificateName)
        {
            //get the Azure key vault location
            _keyVaultUrl = keyVaultUrl;
            
            //get the Azure certificate name
            _vaultCertificateName = vaultCertificateName;

            //Get the Azure certificate reference
            var certClient = new CertificateClient(_keyVaultUrl, new DefaultAzureCredential());
            var azureCertificate = certClient.GetCertificate(_vaultCertificateName).Value;

            //get the private key Uri. The key cannot be exported. It can be only invoked
            _keyVaultCertificatePrivateKeyUrl = azureCertificate.KeyId;

            //set the digital certificate in order to be used on signature creation
            RemoteSignatureCertificate = new X509Certificate2(azureCertificate.Cer);
        }


        public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
        {
            try
            {
                var rsaCryptoClient = new CryptographyClient(_keyVaultCertificatePrivateKeyUrl, new DefaultAzureCredential());

                SignResult rsaSignResult = rsaCryptoClient.SignData(Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS256, dataToSign);

                return rsaSignResult.Signature;

            }
            catch (Exception ex)
            {
                throw new Exception("Remote signature cannot be performed: " + ex.Message);

            }
        }
    }

    class Program
    {
        static void ExtractCertificateInformation(X509Certificate2 cert)
        {
            Console.WriteLine("Certificate subject:" + cert.Subject);
            Console.WriteLine("Certificate issued by:" + cert.GetNameInfo(X509NameType.SimpleName, true));
            Console.WriteLine("Certificate will expire on: " + cert.NotAfter.ToString());
            Console.WriteLine("Certificate is time valid: " + DigitalCertificate.VerifyDigitalCertificate(cert, VerificationType.LocalTime).ToString());
        }

        static void DigitallySignPDFFile(string unsignedDocument, string signedDocument)
        {
            PdfSignature ps = new PdfSignature("your serial number");

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);

            ps.HashAlgorithm = SignLib.HashAlgorithm.SHA256;

            string keyVaultUrl = "https://YOUR-KEYVAULT-NAME.vault.azure.net/";
            string vaultCertificateName = "NAME-OF-THE-CERTIFICATE";

            //Digital signature certificate will be loaded from Azure Key Vault
            ExternalSignature exSignature = new ExternalSignature(new Uri(keyVaultUrl), vaultCertificateName);

            //bind the external signature with the library
            SignLib.Certificates.DigitalCertificate.UseExternalSignatureProvider = exSignature;

            //set the certificate
            ps.DigitalSignatureCertificate = exSignature.RemoteSignatureCertificate;

            //the signature will be timestamped.
            ps.TimeStamping.ServerUrl = new Uri("https://freetsa.org/tsr");

            //write the signed file
            File.WriteAllBytes(signedDocument, ps.ApplyDigitalSignature());

            Console.WriteLine("The PDF signature was created." + Environment.NewLine);

        }

        static void VerifyPDFSignature(string signedDocument)
        {
            PdfSignature ps = new PdfSignature("your serial number");

            ps.LoadPdfDocument(signedDocument);

            Console.WriteLine("Number of signatures: " + ps.DocumentProperties.DigitalSignatures.Count.ToString());

            //verify every digital signature form the PDF document
            foreach (PdfSignatureInfo csi in ps.DocumentProperties.DigitalSignatures)
            {
                Console.WriteLine("Signature name: " + csi.SignatureName);
                Console.WriteLine("Hash Algorithm: " + csi.HashAlgorithm.ToString());
                Console.WriteLine("Signature Certificate Information");
                ExtractCertificateInformation(csi.SignatureCertificate);
                Console.WriteLine("Signature Is Valid: " + csi.SignatureIsValid.ToString());
                Console.WriteLine("Signature Time: " + csi.SignatureTime.ToLocalTime().ToString());
                Console.WriteLine("Is Timestamped: " + csi.SignatureIsTimestamped);

                if (csi.SignatureIsTimestamped == true)
                {
                    Console.WriteLine("Hash Algorithm: " + csi.TimestampInfo.HashAlgorithm.FriendlyName);
                    Console.WriteLine("Is TimestampAltered: " + csi.TimestampInfo.IsTimestampAltered.ToString());
                    Console.WriteLine("TimestampSerial Number: " + csi.TimestampInfo.SerialNumber);
                }

                Console.WriteLine(Environment.NewLine);
            }

            Console.WriteLine("Done PDF signature verification." + Environment.NewLine + Environment.NewLine);
        }

        static void Main(string[] args)
        {
            DigitallySignPDFFile("source.pdf", "source[signed].pdf");
            VerifyPDFSignature("source[signed].pdf");
        }
    }
}
