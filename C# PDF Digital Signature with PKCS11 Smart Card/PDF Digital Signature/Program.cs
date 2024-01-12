using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

//https://www.pkcs11interop.net/
//https://www.nuget.org/packages/Pkcs11Interop/4.0.0
//Install-Package Pkcs11Interop -Version 4.0.0
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;

using SignLib.Pdf;
using SignLib.Certificates;


namespace SignLibTest
{

    class Program
    {

        //This demo project uses Pkcs11Interop library available here: https://www.pkcs11interop.net/
        static string serialNumber = "Your serial number";

        static void DigitallySignPDFFile(string unsignedDocument, string signedDocument)
        {
            string pkcs11DriverPath = @"c:\Windows\System32\eTPKCS11.dll"; //the path to the PKCS#11 smart card/HSM driver
            string smartCardPin = "1234567890"; //Your smart card/HSM PIN
            int slotNumber = 0; //Slot number. Usually it is 0 if you have only one token inserted
            string pathToTheCertificate = @"d:\YourExportedCertificatePublicPart.cer"; //path to your exported public part certificate file (the .CER file)

            PdfSignature ps = new PdfSignature(serialNumber);

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);

            ExternalSignature exSignature = new ExternalSignature(pkcs11DriverPath, smartCardPin, slotNumber);

            //load the certificate from file and not smart card
            //save the .CER file of the certifiate on a separate file and load it
            exSignature.PKCS11SignatureCertificate = new X509Certificate2(File.ReadAllBytes(pathToTheCertificate));

            //set the certificate
            ps.DigitalSignatureCertificate = exSignature.PKCS11SignatureCertificate;

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
        //Install-Package Pkcs11Interop -Version 4.0.0
        string _pkcs11LibraryPath;
        string _smartCardPin;
        int _slotNumber;

        public ExternalSignature(string pathToPKCS11Module, string smartCardPin, int slotNumber)
        {
            _pkcs11LibraryPath = pathToPKCS11Module;
            _smartCardPin = smartCardPin;
            _slotNumber = slotNumber;
        }

        public X509Certificate2 PKCS11SignatureCertificate { get; set; }

        public byte[] ApplySignature(byte[] dataToSign, System.Security.Cryptography.Oid oid)
        {
            try
            {
                // Load unmanaged PKCS#11 library
                using (Pkcs11 pkcs11 = new Pkcs11(_pkcs11LibraryPath, AppType.MultiThreaded))
                {
                    if (pkcs11.GetSlotList(SlotsType.WithTokenPresent).Count == 0)
                        throw new System.Security.Cryptography.CryptographicException("PKCS#11 smart card is not present.");

                    Slot slot = pkcs11.GetSlotList(SlotsType.WithTokenPresent)[_slotNumber];

                    // Open RW session
                    using (Session session = slot.OpenSession(SessionType.ReadOnly))
                    {
                        // Login as normal user
                        session.Login(CKU.CKU_USER, _smartCardPin);

                        // Parse certificate
                        X509CertificateParser x509CertificateParser = new X509CertificateParser();
                        //System.Security.Cryptography.X509Certificates.X509Certificate2 temp_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(PKCS11SignatureCertificate);
                        Org.BouncyCastle.X509.X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(PKCS11SignatureCertificate.RawData);

                        // Get public key from certificate
                        AsymmetricKeyParameter pubKeyParams = x509Certificate.GetPublicKey();
                        if (!(pubKeyParams is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters))
                            throw new NotSupportedException("Only RSA keys are supported");

                        Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaPubKeyParams = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)pubKeyParams;

                        // Find corresponding private key by modulus and exponent
                        List<ObjectAttribute> privKeySearchTemplate = new List<ObjectAttribute>();
                        privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                        privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
                        privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()));
                        privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned()));

                        List<ObjectHandle> privateKeyList = session.FindAllObjects(privKeySearchTemplate);

                        //use the corresponding provate key
                        foreach (ObjectHandle privateKey in privateKeyList)
                        {
                            byte[] digest = null;
                            byte[] digestInfo = null;

                            digest = ComputeDigest(dataToSign, oid.Value);
                            digestInfo = CreateDigestInfo(digest, oid.Value);

                            Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS);

                            return session.Sign(mechanism, privateKey, digestInfo);

                        }

                    }
                }

                //the private key is not present
                throw new Exception("Private key was not found.");

            }
            catch (Exception ex)
            {
                throw new Exception("PKCS#11 signature cannot be performed: " + ex.Message);

            }
        }

        private byte[] ComputeDigest(byte[] message, string hashOid)
        {
            try
            {
                System.Security.Cryptography.HashAlgorithm sha = null;

                if (hashOid == "1.3.14.3.2.26") //SHA1
                    sha = new System.Security.Cryptography.SHA1Managed();

                if (hashOid == "2.16.840.1.101.3.4.2.1") //SHA256
                    sha = new System.Security.Cryptography.SHA256Managed();

                if (hashOid == "2.16.840.1.101.3.4.2.2") //SHA384
                    sha = new System.Security.Cryptography.SHA384Managed();

                if (hashOid == "2.16.840.1.101.3.4.2.3") //SHA512
                    sha = new System.Security.Cryptography.SHA512Managed();

                return sha.ComputeHash(message);

            }
            catch
            {
                throw;
            }
        }

        private byte[] CreateDigestInfo(byte[] hash, string hashOid)
        {
            Org.BouncyCastle.Asn1.DerObjectIdentifier derObjectIdentifier = new Org.BouncyCastle.Asn1.DerObjectIdentifier(hashOid);
            Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier algorithmIdentifier = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(derObjectIdentifier, null);
            Org.BouncyCastle.Asn1.X509.DigestInfo digestInfo = new Org.BouncyCastle.Asn1.X509.DigestInfo(algorithmIdentifier, hash);
            return digestInfo.GetDerEncoded();
        }
    }

}


