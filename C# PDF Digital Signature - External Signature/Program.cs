using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;

using SignLib.Pdf;
using SignLib.Certificates;
using System.Security.Cryptography;

namespace SignLibTest
{

    class Program
    {

        static string serialNumber = "Your serial number";

        static void DigitallySignPDFFile(string unsignedDocument, string signedDocument)
        {
            string certificateSubject = "Test PFX Certificate"; //certificate subject (CN=)
            //string certificateSubject = "test"; //certificate subject (CN=)

            PdfSignature ps = new PdfSignature(serialNumber);

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);

            ps.HashAlgorithm = SignLib.HashAlgorithm.SHA256;

            ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(false, DigitalCertificateSearchCriteria.CommonNameCN, certificateSubject, false);

            ExternalSignature exSignature = new ExternalSignature(ps.DigitalSignatureCertificate);

            //bind the external signature with the library
            DigitalCertificate.UseExternalSignatureProvider = exSignature;

            //write the signed file
            File.WriteAllBytes(signedDocument, ps.ApplyDigitalSignature());

            Console.WriteLine("The PDF signature was created." + Environment.NewLine);

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
                    Console.WriteLine("TimestampSerial Number: " + csi.TimestampInfo.SerialNumber);
                }

                Console.WriteLine(Environment.NewLine);
            }

            Console.WriteLine("Done PDF signature verification." + Environment.NewLine + Environment.NewLine);
        }

        static void ExtractCertificateInformation(X509Certificate2 cert)
        {
            Console.WriteLine("Certificate subject:" + cert.Subject);
            Console.WriteLine("Certificate issued by:" + cert.GetNameInfo(X509NameType.SimpleName, true));
            Console.WriteLine("Certificate will expire on: " + cert.NotAfter.ToString());
            Console.WriteLine("Certificate is time valid: " + DigitalCertificate.VerifyDigitalCertificate(cert, VerificationType.LocalTime).ToString());
        }

        static void Main(string[] args)
        {
            try
            {
                DigitallySignPDFFile("source.pdf", "source[signed].pdf");
                VerifyPDFSignature("source[signed].pdf");

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }

    /// <summary>
    /// Create the external signature using a third party engine. The class must be inherited from SignLib.Certificates.IExternalSignature interface and 
    /// must implements the method public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
    /// </summary>
    public class ExternalSignature : SignLib.Certificates.IExternalSignature
    {
        // Defines path to unmanaged PKCS#11 library provided by the cryptographic device vendor
        X509Certificate2 _cert;
        public ExternalSignature(X509Certificate2 cert)
        {
            _cert = cert;
        }

        public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
        {
            if (_cert.HasPrivateKey == false)
                throw new System.Security.Cryptography.CryptographicException("The private key for this certificate was not found.");

            try
            {

                HashAlgorithmName hashAlg = HashAlgorithmName.SHA1;

                if (oid.Value == new Oid("SHA1").Value) //SHA1
                    hashAlg = HashAlgorithmName.SHA1;

                if (oid.Value == new Oid("SHA256").Value) //SHA256
                    hashAlg = HashAlgorithmName.SHA256;

                if (oid.Value == new Oid("SHA384").Value) //SHA384
                    hashAlg = HashAlgorithmName.SHA384;

                if (oid.Value == new Oid("SHA512").Value) //SHA512
                    hashAlg = HashAlgorithmName.SHA512;

                System.Security.Cryptography.RSACng rsaSignature = _cert.GetRSAPrivateKey() as System.Security.Cryptography.RSACng;

                return rsaSignature.SignData(dataToSign, hashAlg, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                throw new System.Security.Cryptography.CryptographicException(ex.Message);
            }
        }
    }

}


