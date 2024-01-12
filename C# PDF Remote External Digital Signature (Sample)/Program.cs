using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Security.Cryptography.X509Certificates;

using SignLib.Certificates;
using SignLib.Pdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using System.Text;
using System.Security.Cryptography;

namespace SignLibTest
{
    /// <summary>
    /// Create the external signature using a third party engine. The class must be inherited from SignLib.Certificates.IExternalSignature interface and 
    /// must implements the method public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
    /// </summary>
    public class ExternalSignature : SignLib.Certificates.IExternalSignature
    {

        public ExternalSignature()
        {
          
        }

        private byte[] GetSignedHashFromRemoteServer(byte[] hashToSign)
        {
            //TODO: the byte[] hashToSign is sent to the Remote Signature Server
            //and the signed hash is returned

            //the byte[] hashToSign is sent to the Remote Signature Server
            return Encoding.UTF8.GetBytes("The byte[] hashToSign is sent to the Remote Signature Server and the signedHash returned by the Server will be added on the digital signature");
        }

        public X509Certificate2 RemoteSignatureCertificate { get; set; }

        public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
        {
            try
            {
                //the hash algorithm is considered SHA-256

                //create the PDF data hash
                HashAlgorithm hashAlg = SHA256.Create();

                //calculate the hash of the PDF data
                byte[] pdfDataHash = hashAlg.ComputeHash(dataToSign);

                //the signed hash sent by the Remote Signature Server and 
                //the signature result is added on the PDF signature block
                return GetSignedHashFromRemoteServer(pdfDataHash);

            }
            catch (Exception ex)
            {
                throw new Exception("Remote signature cannot be performed: " + ex.Message);

            }
        }
    }

    class Program
    {

        static string serialNumber = "your serial number";

        static void DigitallySignPDFFile(string unsignedDocument, string signedDocument)
        {
            PdfSignature ps = new PdfSignature(serialNumber);

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);
            ps.SignaturePosition = SignaturePosition.TopRight;
            ps.SigningReason = "I approve this document";
            ps.SigningLocation = "Accounting department";

            ps.SignaturePosition = SignaturePosition.TopLeft;

            ps.HashAlgorithm = SignLib.HashAlgorithm.SHA256;

            ExternalSignature exSignature = new ExternalSignature();

            //the public part of the certificate must be loaded to prepare the digital signature
            //it is the .CER, .CRT, .PEM public part of the certificate
            //it can be exported from an already signed file 
            //it can be obtained from the Certification Autority that issued the certificate

            //set the certificate
            ps.DigitalSignatureCertificate = exSignature.RemoteSignatureCertificate;

            //bind the external signature with the library
            SignLib.Certificates.DigitalCertificate.UseExternalSignatureProvider = exSignature;

            //write the signed file
            File.WriteAllBytes(signedDocument, ps.ApplyDigitalSignature());

            Console.WriteLine("The PDF signature was created." + Environment.NewLine);

        }


        static void Main(string[] args)
        {
            try
            {
                DigitallySignPDFFile("source.pdf", "source[signed].pdf");

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


