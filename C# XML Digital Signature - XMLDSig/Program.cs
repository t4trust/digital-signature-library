using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;

using System.Security.Cryptography.X509Certificates;
using SignLib;
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

        static void DigitallySignXMLDocument(string unsignedDocument, string signedDocument)
        {
            XmlSignatureSha256 cs = new XmlSignatureSha256(serialNumber);

            //Digital signature certificate can be loaded from various sources

            //Load the signature certificate from a PFX or P12 file
            X509Certificate2 cert = new X509Certificate2(Environment.CurrentDirectory + "\\cert.pfx", "123456", X509KeyStorageFlags.Exportable);
            cs.DigitalSignatureCertificate = cert;


            //Load the certificate from Microsoft Store. 
            //The smart card or USB token certificates are usually available on Microsoft Certificate Store (start - run - certmgr.msc).
            //If the smart card certificate not appears on Microsoft Certificate Store it cannot be used by the library
            //cs.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(false, string.Empty, "Select Certificate", "Select the certificate for digital signature");

            //The smart card PIN dialog can be bypassed for some smart cards/USB Tokens. 
            //ATTENTION: This feature will NOT work for all available smart card/USB Tokens becauase of the drivers or other security measures.
            //Use this property carefully.
            //DigitalCertificate.SmartCardPin = "123456";

            cs.IncludeKeyInfo = true;
            cs.IncludeSignatureCertificate = true;

            //apply the digital signature
            cs.ApplyDigitalSignature(unsignedDocument, signedDocument);

            Console.WriteLine("XML signature was created." + Environment.NewLine);

        }

        static void VerifyXMLSignature(string signedDocument)
        {
            XmlSignature cv = new XmlSignature(serialNumber);

            Console.WriteLine("Number of signatures: " + cv.GetNumberOfSignatures(signedDocument));

            //signature algorithm
            Console.WriteLine("Signature algorithm: " + cv.GetSignatureAlgorithm(signedDocument));

            Console.WriteLine("Done XML signature verification." + Environment.NewLine + Environment.NewLine);
        }


        static void Main(string[] args)
        {
            try
            {

                DigitallySignXMLDocument(Environment.CurrentDirectory + "\\test.xml", Environment.CurrentDirectory + "\\test[signed].xml");

                VerifyXMLSignature(Environment.CurrentDirectory + "\\test[signed].xml");

                Console.WriteLine("All done!");

            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


