using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;

using System.Security.Cryptography.X509Certificates;
using SignLib.Certificates;
using SignLib.Cades;
using SignLib.Pdf;

namespace SignLibTest
{
    class Program
    {
        /*************************************
        On the demo version of the library, a 10 seconds delay will be added for every operation.
        */
        static string serialNumber = "YourSerialNumber";

        static void DigitallySignInPDFFormat(string sourceFolderPath, string destinationFolderPath)
        {
            PdfSignature ps = new PdfSignature(serialNumber);

            //Digital signature certificate can be loaded from various sources

            //Load the signature certificate from a PFX or P12 file
            ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(Environment.CurrentDirectory + "\\cert.pfx", "123456");

            //Load the certificate from Microsoft Store. 
            //The smart card or USB token certificates are usually available on Microsoft Certificate Store (start - run - certmgr.msc).
            //If the smart card certificate not appears on Microsoft Certificate Store it cannot be used by the library
            //ps.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(false, string.Empty, "Select Certificate", "Select the certificate for digital signature");

            //The smart card PIN dialog can be bypassed for some smart cards/USB Tokens. 
            //ATTENTION: This feature will NOT work for all available smart card/USB Tokens becauase of the drivers or other security measures.
            //Use this property carefully.
            //DigitalCertificate.SmartCardPin = "123456";

            //optionally, the signature can be timestamped.
            //ps.TimeStamping.ServerUrl = new Uri("https://freetsa.org/tsr");


            System.IO.DirectoryInfo di;
            System.IO.FileInfo[] rgFiles;
            //get the pdf files from the folder
            di = new System.IO.DirectoryInfo(sourceFolderPath);
            //select only the PDF files
            rgFiles = di.GetFiles("*.pdf");
            Console.WriteLine("Number of files that will be signed in PDF format: " + rgFiles.Length.ToString());

            foreach (FileInfo fi in rgFiles)
            {
                //for readonly files
                fi.Attributes = FileAttributes.Normal;

                //load the PDF document
                ps.LoadPdfDocument(sourceFolderPath + fi.Name);

                //write the signed file
                File.WriteAllBytes(destinationFolderPath + fi.Name, ps.ApplyDigitalSignature());

                Console.WriteLine("File " + fi.Name + " was signed in PDF format");
            }

        }

        static void DigitallySignInCAdESFormat(string sourceFolderPath, string destinationFolderPath)
        {
            CadesSignature cs = new CadesSignature(serialNumber);

            //Digital signature certificate can be loaded from various sources

            //Load the signature certificate from a PFX or P12 file
            cs.DigitalSignatureCertificate = DigitalCertificate.LoadCertificate(Environment.CurrentDirectory + "\\cert.pfx", "123456");

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



            System.IO.DirectoryInfo di;
            System.IO.FileInfo[] rgFiles;
            //get the pdf files from the folder
            di = new System.IO.DirectoryInfo(sourceFolderPath);
            //select all files
            rgFiles = di.GetFiles("*.*");
            Console.WriteLine("Number of files that will be signed in CAdES format: " + rgFiles.Length.ToString());

            foreach (FileInfo fi in rgFiles)
            {
                //for readonly files
                fi.Attributes = FileAttributes.Normal;

                //write the signed file
                //usually, the signed CAdES file should be saved with .p7s or .p7m extension
                File.WriteAllBytes(destinationFolderPath + fi.Name, cs.ApplyDigitalSignature(sourceFolderPath + fi.Name + ".p7m"));

                Console.WriteLine("File " + fi.Name + " was signed in CAdES format");
            }

        }

        static void Main(string[] args)
        {
            try
            {
                //digitally sign all pdf files available on the source_folder
                DigitallySignInPDFFormat(Environment.CurrentDirectory + "\\source_folder\\", Environment.CurrentDirectory + "\\destination_folder\\");

                //usually, the signed CAdES file should be saved with .p7s or .p7m extension
                //DigitallySignInCAdESFormat(Environment.CurrentDirectory + "\\source_folder\\", Environment.CurrentDirectory + "\\destination_folder\\");

                

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


