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

        static void AddTimestampSignatureToPdfFile(string unsignedDocument, string signedDocument)
        {
            PdfSignature ps = new PdfSignature(serialNumber);

            //load the PDF document
            ps.LoadPdfDocument(unsignedDocument);

            ps.TimeStamping.ServerUrl = new Uri("https://freetsa.org/tsr");

            //write the signed file
            File.WriteAllBytes(signedDocument,  ps.ApplyTimestampSignature());

            Console.WriteLine("The PDF timestamp signature was created." + Environment.NewLine);

        }

        static void Main(string[] args)
        {
            try
            {
                AddTimestampSignatureToPdfFile(Environment.CurrentDirectory + "\\source.pdf", Environment.CurrentDirectory + "\\source[signed].pdf");

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


