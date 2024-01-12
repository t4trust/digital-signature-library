using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using SignLib.Certificates;
using SignLib.Pdf;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PDF_Digital_Signature
{
    class Program
    {
        static void ExtractCertificateInformation(X509Certificate2 cert)
        {
            Console.WriteLine("Certificate subject:" + cert.Subject);
            Console.WriteLine("Certificate issued by:" + cert.GetNameInfo(X509NameType.SimpleName, true));
            Console.WriteLine("Certificate will expire on: " + cert.NotAfter.ToString());
            Console.WriteLine("Certificate is time valid: " + DigitalCertificate.VerifyDigitalCertificate(cert, VerificationType.LocalTime).ToString());
        }

        static byte[] GetCertificateFromAzureKeyVault(string keyVaultUrl, string vaultCertificateName)
        {

            var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

            KeyVaultSecret secret = client.GetSecret(vaultCertificateName);

            return System.Convert.FromBase64String(secret.Value);
        }

        static void DigitallySignPDFFile(string unsignedDocument, string signedDocument)
        {
            PdfSignature ps = new PdfSignature("c2b976df995c9f3a006b");

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);
            ps.SignaturePosition = SignaturePosition.TopRight;
            ps.SigningReason = "I approve this document";
            ps.SigningLocation = "Accounting department";

            ps.SignaturePosition = SignaturePosition.TopLeft;

            ps.HashAlgorithm = SignLib.HashAlgorithm.SHA256;


            //Digital signature certificate will be loaded from Azure Key Vault

            string keyVaultUrl = "https://YOUR-KEYVAULT-NAME.vault.azure.net/";
            string vaultCertificateName = "NAME-OF-THE-CERTIFICATE";

            //the certificate is downloaded as PFX without password
            byte[] azureKeyVaultCertificate = GetCertificateFromAzureKeyVault(keyVaultUrl, vaultCertificateName);

            //Load the signature certificate from byte array
            ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(azureKeyVaultCertificate, "");

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
