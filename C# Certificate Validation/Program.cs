using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Net;
 

using System.Security.Cryptography.X509Certificates;
using SignLib;
using SignLib.Certificates;


namespace SignLibTest
{

    class Program
    {
        static void VerifyCertificate()
        {

            //check if the certificate is time valid
            //Verify the certificate issued for google.com website
            X509Certificate2 certificate = new X509Certificate2("d:\\your_certificate_to_validate.cer");

            Console.WriteLine("Verify against the local time: " + DigitalCertificate.VerifyDigitalCertificate(certificate, VerificationType.LocalTime));
            Console.WriteLine("Verify against the CRL: " + DigitalCertificate.VerifyDigitalCertificate(certificate, VerificationType.CRL));
            Console.WriteLine("Verify against the OCSP: " + DigitalCertificate.VerifyDigitalCertificate(certificate, VerificationType.OCSP));

            //CertificateStatus.Expired - the certificate is expired
            //CertificateStatus.Revoked - the certificate is revoked 
            //CertificateStatus.Unknown - the CRL or the OCSP service is unavailable
            //CertificateStatus.Valid - the certificate is OK


            Console.WriteLine("Done certificate validation.");

        }

        static void Main(string[] args)
        {
            try
            {
                VerifyCertificate();

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


