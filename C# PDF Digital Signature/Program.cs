using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;

using System.Security.Cryptography.X509Certificates;
using SignLib.Certificates;
using SignLib.Pdf;

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

        static void DigitallySignPDFFile(string unsignedDocument, string signedDocument)
        {
            PdfSignature ps = new PdfSignature(serialNumber);

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);
            ps.SignaturePosition = SignaturePosition.TopRight;
            ps.SigningReason = "I approve this document";
            ps.SigningLocation = "Accounting department";

            ps.SignaturePosition = SignaturePosition.TopLeft;


            //Digital signature certificate can be loaded from various sources

            //Load the signature certificate from a PFX or P12 file
            ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(Environment.CurrentDirectory + "\\cert.pfx", "123456");

            //Create a digital signature certificate on the fly (X509Certificate2 certificate)
            //ps.DigitalSignatureCertificate = CreateDigitalCertificate();

            //Load the certificate from Microsoft Store. 
            //The smart card or USB token certificates are usually available on Microsoft Certificate Store (start - run - certmgr.msc).
            //If the smart card certificate not appears on Microsoft Certificate Store it cannot be used by the library
            //ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(false, string.Empty, "Select Certificate", "Select the certificate for digital signature");

            //write the signed file
            File.WriteAllBytes(signedDocument, ps.ApplyDigitalSignature());

            Console.WriteLine("The first PDF signature was created." + Environment.NewLine);

        }

        static void DigitallySignPDFFileAdvanced(string unsignedDocument, string signedDocument)
        {
            PdfSignature ps = new PdfSignature(serialNumber);

            //load the PDF document
            ps.LoadPdfDocument(File.ReadAllBytes(unsignedDocument));

            ps.SignatureAdvancedPosition = new System.Drawing.Rectangle(10, 10, 400, 150);
            ps.SigningReason = "I approve this document";
            ps.SigningLocation = "Accounting department";

            //Digital signature certificate can be loaded from vorious sources

            //Load the signature certificate from a PFX or P12 file
            ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(Environment.CurrentDirectory + "\\cert.pfx", "123456");

            //Create a digital signature certificate on the fly (X509Certificate2 certificate)
            //ps.DigitalSignatureCertificate = CreateDigitalCertificate();

            //Load the certificate from Microsoft Store. 
            //The smart card or USB token certificates are usually available on Microsoft Certificate Store (start - run - certmgr.msc).
            //If the smart card certificate not appears on Microsoft Certificate Store it cannot be used by the library
            //ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(false, string.Empty, "Select Certificate", "Select the certificate for digital signature");

            //The smart card PIN dialog can be bypassed for some smart cards/USB Tokens. 
            //ATTENTION: This feature will NOT work for all available smart card/USB Tokens becauase of the drivers or other security measures.
            //Use this property carefully.
            //DigitalCertificate.SmartCardPin = "123456";


            ps.SignatureImage = File.ReadAllBytes(Environment.CurrentDirectory + "\\signature_image.jpg");
            ps.SignatureImageType = SignatureImageType.ImageAndText;
            ps.SignatureText = "Siganture created by: " + ps.DigitalSignatureCertificate.GetNameInfo(X509NameType.SimpleName, false) + Environment.NewLine + "Date: " + DateTime.Now.ToString("dd.MM.yyyy HH:mm");

            ps.HashAlgorithm = SignLib.HashAlgorithm.SHA256;

            //PAdES-BES signature. Requires Adobe X
            //ps.SignatureStandard = SignLib.SignatureStandard.Cades;

            ps.CertifySignature = CertifyMethod.AnnotationsAndFormFilling;

            //the signature will be timestamped.
            //ps.TimeStamping.ServerUrl = new Uri("https://freetsa.org/tsr");

            //write the signed file
            File.WriteAllBytes(signedDocument, ps.ApplyDigitalSignature());

            Console.WriteLine("The second PDF signature was created." + Environment.NewLine);

        }

        static void VerifyPDFSignature(string signedDocument)
        {
            PdfSignature ps = new PdfSignature(serialNumber);

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
                    Console.WriteLine("TSA Certificate: " + csi.TimestampInfo.TsaCertificate.Subject);
                }

                Console.WriteLine(Environment.NewLine);
            }

            Console.WriteLine("Done PDF signature verification." + Environment.NewLine + Environment.NewLine);
        }


        static void Main(string[] args)
        {
            try
            {



                DigitallySignPDFFile(Environment.CurrentDirectory + "\\source.pdf", Environment.CurrentDirectory + "\\source[signed].pdf");

                //add a second signature using a certificate created on the fly
                DigitallySignPDFFileAdvanced(Environment.CurrentDirectory + "\\source[signed].pdf", Environment.CurrentDirectory + "\\source[signed2].pdf");

                VerifyPDFSignature(Environment.CurrentDirectory + "\\source[signed2].pdf");

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


