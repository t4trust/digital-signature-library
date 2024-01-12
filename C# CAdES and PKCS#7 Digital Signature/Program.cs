using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;

using System.Security.Cryptography.X509Certificates;
using SignLib.Certificates;
using SignLib.Cades;

namespace SignLibTest
{
    class Program
    {
        /*************************************
        On the demo version of the library, a 10 seconds delay will be added for every operation.
        The certificate will be valid only 30 days on the demo version of the library
        */
        static string serialNumber = "YourSerialNumber";

        static X509Certificate2 CreateDigitalCertificate()
        {
            string certificatePassword = "temp_passw0rd";
            //on the demo version the certificates will be valid 30 days only
            //this is the single restriction of the library in demo mode
            X509CertificateGenerator certGenerator = new X509CertificateGenerator(serialNumber);

            //set the validity of the certificate
            certGenerator.ValidFrom = DateTime.Now;
            //The certificate will be valid only 30 days on the demo version of the library
            certGenerator.ValidTo = DateTime.Now.AddYears(2);

            //set the signing algorithm and the key size
            certGenerator.KeySize = KeySize.KeySize1024Bit;
            certGenerator.SignatureAlgorithm = SignatureAlgorithm.SHA256WithRSA;

            //set the certificate sobject
            certGenerator.Subject = "CN=Digital Signature Certificate, OU=Organization Unit, E=user@email.com";

            //add some simple extensions to the client certificate
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.DigitalSignature);
            certGenerator.Extensions.AddKeyUsage(CertificateKeyUsage.NonRepudiation);

            //add some enhanced extensions to the client certificate marked as critical
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.DocumentSigning);
            certGenerator.Extensions.AddEnhancedKeyUsage(CertificateEnhancedKeyUsage.ClientAuthentication);

            Console.WriteLine("User certificate was created!");

            //convert the resulting PFX certificate to X509Certificate2 that can be used by .NET
            return new X509Certificate2(certGenerator.GenerateCertificate(certificatePassword, false), certificatePassword);
        }

        static void ExtractCertificateInformation(X509Certificate2 cert)
        {
            Console.WriteLine("Certificate subject:" + cert.Subject);
            Console.WriteLine("Certificate issued by:" + cert.GetNameInfo(X509NameType.SimpleName, true));
            Console.WriteLine("Certificate will expire on: " + cert.NotAfter.ToString());
            Console.WriteLine("Certificate is time valid: " + DigitalCertificate.VerifyDigitalCertificate(cert, VerificationType.LocalTime).ToString());
        }

        static void DigitallySignInCAdESFormat(string unsignedDocument, string signedDocument)
        {
            CadesSignature cs = new CadesSignature(serialNumber);

            //Digital signature certificate can be loaded from various sources

            //Load the signature certificate from a PFX or P12 file
            cs.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(Environment.CurrentDirectory + "\\cert.pfx", "123456");

            //Create a digital signature certificate on the fly (X509Certificate2 certificate)
            //cs.DigitalSignatureCertificate = CreateDigitalCertificate();

            //Load the certificate from Microsoft Store. 
            //The smart card or USB token certificates are usually available on Microsoft Certificate Store (start - run - certmgr.msc).
            //If the smart card certificate not appears on Microsoft Certificate Store it cannot be used by the library
            //cs.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(false, string.Empty, "Select Certificate", "Select the certificate for digital signature");

            //The smart card PIN dialog can be bypassed for some smart cards/USB Tokens. 
            //ATTENTION: This feature will NOT work for all available smart card/USB Tokens becauase of the drivers or other security measures.
            //Use this property carefully.
            //DigitalCertificate.SmartCardPin = "123456";

            //optionally, the signature can be timestamped.
            //cs.TimeStamping.ServerUrl = new Uri("https://freetsa.org/tsr");

            //write the signed file
            //usually, the signed CAdES file should be saved with .p7s or .p7m extension
            File.WriteAllBytes(signedDocument, cs.ApplyDigitalSignature(unsignedDocument));

            Console.WriteLine("The CAdES signature was created." + Environment.NewLine);

        }

        static void VerifyCAdESSignature(string signedDocument)
        {
            CadesVerify cv = new CadesVerify(signedDocument, serialNumber);

            Console.WriteLine("Number of signatures: " + cv.Signatures.Count.ToString());

            //verify every digital signature from the signed document
            foreach (CadesSignatureInfo csi in cv.Signatures)
            {
                Console.WriteLine("Hash Algorithm: " + csi.HashAlgorithm.FriendlyName);
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
                    Console.WriteLine("TSA Certificate: " + csi.TimestampInfo.TsaCertificate.Subject);
                }

                Console.WriteLine(Environment.NewLine);
            }

            Console.WriteLine("Done CAdES signature verification." + Environment.NewLine + Environment.NewLine);
        }

        static void Main(string[] args)
        {
            try
            {
                //usually, the signed CAdES file should be saved with .p7s or .p7m extension
                DigitallySignInCAdESFormat(Environment.CurrentDirectory + "\\test.txt", Environment.CurrentDirectory + "\\test.txt.p7s");

                VerifyCAdESSignature(Environment.CurrentDirectory + "\\test.txt.p7s");

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


