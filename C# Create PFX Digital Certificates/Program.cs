using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;

using System.Security.Cryptography.X509Certificates;
using SignLib.Certificates;

namespace SignLibTest
{

    class Program
    {
        /*************************************
        On the demo version of the library, a 10 seconds delay will be added for every operation.
        The certificate will be valid only 30 days on the demo version of the library
        */
        static string serialNumber = "YourSerialNumber";

        static void CreateRootCertificateAsPFX(string RootCertificatePath, string RootCertificatePassword)
        {

            //on the demo version the certificates will be valid 30 days only
            //this is the single restriction of the library in demo mode
            X509CertificateGenerator certGenerator = new X509CertificateGenerator(serialNumber);

            //set the validity of the certificate
            certGenerator.ValidFrom = DateTime.Now;
            //The certificate will be valid only 30 days on the demo version of the library
            certGenerator.ValidTo = DateTime.Now.AddYears(2);

            //set the signing algorithm and the key size
            certGenerator.KeySize = KeySize.KeySize1024Bit;
            certGenerator.SignatureAlgorithm = SignatureAlgorithm.SHA1WithRSA;

            certGenerator.AddToSubject(SubjectType.E, "root@email.com");
            certGenerator.AddToSubject(SubjectType.OU, "Organization Unit Root");
            certGenerator.AddToSubject(SubjectType.CN, "Root certificate, master");

            //also you can use an alternative method
            certGenerator.Subject = "CN=Root certificate master, OU=Organization Unit Root, E=root@email.com";

            //add some extensions to the Root certificate
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DigitalSignature);
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DataEncipherment);
            certGenerator.Extensions.KeyUsageIsCritical = false;

            //certGenerator.FriendlyName = "Test Root Certificate";

            //create the PFX certificate as Root certificate
            File.WriteAllBytes(RootCertificatePath, certGenerator.GenerateCertificate(RootCertificatePassword, true));

            //save the public part of the certificate
            File.WriteAllBytes(RootCertificatePath + ".cer", new X509Certificate2(RootCertificatePath, RootCertificatePassword).RawData);

            Console.WriteLine("Root certificate was created!");
        }

        static void CreateUserCertificateAsPFX(string RootCertificatePath, string RootCertificatePassword, string ClientCertificatePath, string ClientCertificatePassword)
        {
            //on the demo version the certificates will be valid 30 days only
            //this is the single restriction of the library in demo mode
            X509CertificateGenerator certGenerator = new X509CertificateGenerator(serialNumber);

            //set the validity of the certificate
            certGenerator.ValidFrom = DateTime.Now;
            //The certificate will be valid only 30 days on the demo version of the library
            certGenerator.ValidTo = DateTime.Now.AddMonths(6);

            //load the Root Certificate to sign the user certificate
            certGenerator.LoadRootCertificate(File.ReadAllBytes(RootCertificatePath), RootCertificatePassword);

            //set the signing algorithm and the key size
            certGenerator.KeySize = KeySize.KeySize1024Bit;
            certGenerator.SignatureAlgorithm = SignatureAlgorithm.SHA1WithRSA;

            certGenerator.AddToSubject(SubjectType.E, "user@email.com");
            certGenerator.AddToSubject(SubjectType.OU, "Organization Unit User Certificate");
            certGenerator.AddToSubject(SubjectType.CN, "Simple user certificate");

            //also you can use an alternative method
            //certGenerator.Subject = "CN=Simple user certificate, OU=Organization Unit User Certificate, E=user@email.com";

            //add some simple extensions to the client certificate
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DigitalSignature);
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DataEncipherment);
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.NonRepudiation);

            //add some enhanced extensions to the client certificate marked as critical
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.CodeSigning);
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.SecureEmail);
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.SmartcardLogon);
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.TimeStamping);
            certGenerator.Extensions.KeyUsageIsCritical = true;

            //optionally, set a friendly name
            //certGenerator.FriendlyName = "Simple Client Certificate";

            //create the PFX certificate as user certificate
            File.WriteAllBytes(ClientCertificatePath, certGenerator.GenerateCertificate(ClientCertificatePassword, false));

            //save the public part of the certificate
            File.WriteAllBytes(ClientCertificatePath + ".cer", new X509Certificate2(ClientCertificatePath, ClientCertificatePassword).RawData);

            Console.WriteLine("User certificate was created!");
        }

        static void CreateSelfSignedUserCertificateAsPFX(string ClientCertificatePath, string ClientCertificatePassword)
        {
            //on the demo version the certificates will be valid 30 days only
            //this is the single restriction of the library in demo mode
            X509CertificateGenerator certGenerator = new X509CertificateGenerator(serialNumber);

            //set the validity of the certificate
            certGenerator.ValidFrom = DateTime.Now;
            //The certificate will be valid only 30 days on the demo version of the library
            certGenerator.ValidTo = DateTime.Now.AddDays(100);

            //set the signing algorithm and the key size
            certGenerator.KeySize = KeySize.KeySize1024Bit;
            certGenerator.SignatureAlgorithm = SignatureAlgorithm.SHA1WithRSA;

            //set the certificate sobject
            certGenerator.Subject = "CN=Self signed certificate, OU=Organization Unit, E=selfsigned@email.com";

            //add some simple extensions to the client certificate
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DigitalSignature);
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DataEncipherment);

            //add some enhanced extensions to the client certificate marked as critical
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.DocumentSigning);
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.SecureEmail);

            //create the PFX certificate as user certificate
            File.WriteAllBytes(ClientCertificatePath, certGenerator.GenerateCertificate(ClientCertificatePassword, false));

            //save the public part of the certificate
            File.WriteAllBytes(ClientCertificatePath + ".cer", new X509Certificate2(ClientCertificatePath, ClientCertificatePassword).RawData);

            Console.WriteLine("Self signed user certificate was created!");
        }

        static void ExtractCertificateInformation(string CertificatePath, string CertificatePassword)
        {
            //create a .NET X509Certificate2 object from a PFX file
            X509Certificate2 cert = new X509Certificate2(CertificatePath, CertificatePassword);

            Console.WriteLine("Certificate subject:" + cert.Subject);
            Console.WriteLine("Certificate issued by:" + cert.GetNameInfo(X509NameType.SimpleName, true));
            Console.WriteLine("Certificate will expire on: " + cert.NotAfter.ToString());
            Console.WriteLine("Certificate is time valid: " + DigitalCertificate.VerifyDigitalCertificate(cert, VerificationType.LocalTime).ToString());
        }

        static void Main(string[] args)
        {
            try
            {
                //put all certificates in a single directory
                string certDir = Environment.CurrentDirectory;

                //create the Root certificate as PFX. It will be used to sign the client certificates
                CreateRootCertificateAsPFX(certDir + "\\root_certificate.pfx", "123456");

                //create a client certificate signed by the Root Certificate
                CreateUserCertificateAsPFX(certDir + "\\root_certificate.pfx", "123456", certDir + "\\client_certificate.pfx", "123456");

                //create a self signed certificate
                CreateSelfSignedUserCertificateAsPFX(certDir + "\\self_signed_client_certificate.pfx", "123456");

                ExtractCertificateInformation(certDir + "\\client_certificate.pfx", "123456");


                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


