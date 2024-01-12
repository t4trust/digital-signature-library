

using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Security.Cryptography.X509Certificates;

using SignLib.Certificates;
using SignLib.Pdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

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
            //obtaining the remote signature certificate
            ServiceReferenceRemoteSignature.RemoteSignatureSoapClient rs = new ServiceReferenceRemoteSignature.RemoteSignatureSoapClient(ServiceReferenceRemoteSignature.RemoteSignatureSoapClient.EndpointConfiguration.RemoteSignatureSoap);

            RemoteSignatureCertificate = new X509Certificate2(rs.GetSigningCertificate());
        }

        public X509Certificate2 RemoteSignatureCertificate { get; set; }

        public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
        {
            try
            {
                //only the document hash is sent to the Remote Signature Server
                ServiceReferenceRemoteSignature.RemoteSignatureSoapClient rs = new ServiceReferenceRemoteSignature.RemoteSignatureSoapClient(ServiceReferenceRemoteSignature.RemoteSignatureSoapClient.EndpointConfiguration.RemoteSignatureSoap);
                return rs.RemoteSignWithOid(dataToSign, oid.Value.ToString());

            }
            catch (Exception ex)
            {
                throw new Exception("Remote signature cannot be performed: " + ex.Message);

            }
        }
    }

    class Program
    {

        /*************************************
        On the demo version of the library, a 10 seconds delay will be added for every operation.
        The certificate will be valid only 30 days on the demo version of the library
        */
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

            //set the certificate
            ps.DigitalSignatureCertificate = exSignature.RemoteSignatureCertificate;

            //bind the external signature with the library
            SignLib.Certificates.DigitalCertificate.UseExternalSignatureProvider = exSignature;

            //write the signed file
            File.WriteAllBytes(signedDocument, ps.ApplyDigitalSignature());

            Console.WriteLine("The PDF remote signature was created." + Environment.NewLine);

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




