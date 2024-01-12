using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;

using System.Security.Cryptography.X509Certificates;
using SignLib;
using SignLib.Timestamping;


namespace SignLibTest
{

    class Program
    {
        /*************************************
        On the demo version of the library, a 10 seconds delay will be added for every operation.
        */
        static string serialNumber = "YourSerialNumber";

        static void TimestampAndVerify(string sourceFile, string timestampResponseFile)
        {
            TimestampClient tsa = new TimestampClient(serialNumber);

            tsa.TimeStamping.ServerUrl = new Uri("https://freetsa.org/tsr");

            File.WriteAllBytes(timestampResponseFile, tsa.ObtainTimestamp(sourceFile));

            //display the information obtained from the timestamp file
            TimestampInfo tsaInfo = TimestampInfo.GetInfoFromTsaResponse(File.ReadAllBytes(timestampResponseFile));

            Console.WriteLine("Is Timestamp Altered: " + tsaInfo.IsTimestampAltered.ToString());
            Console.WriteLine("Hash Algorithm: " + tsaInfo.HashAlgorithm.FriendlyName);
            Console.WriteLine("Serial Number: " + tsaInfo.SerialNumber);
            Console.WriteLine("Tsa Certificate: " + tsaInfo.TsaCertificate.Subject);
            Console.WriteLine("Timestamp Time: " + tsaInfo.SignatureTime.ToLocalTime().ToString());

            //we should verify the timestamp response against the original file
            try
            {
                TimestampInfo.IsTsaReponseFileValid(File.ReadAllBytes(sourceFile), File.ReadAllBytes(timestampResponseFile));
                //if no exception is thrown, there is a match between the timestamp and the original file

                Console.WriteLine("The TSA Response file is valid.");
            }

            catch (Exception ex)
            {
                Console.WriteLine("An error has occurred on TSA verification: " + ex.Message);
            }

            Console.WriteLine("Done Timestamping!" + Environment.NewLine + Environment.NewLine);

        }

        static void Main(string[] args)
        {
            try
            {
                TimestampAndVerify(Environment.CurrentDirectory + "\\test.txt", Environment.CurrentDirectory + "\\test.txt.tsr");

                Console.WriteLine("All done!");
            }
            catch (Exception ex)
            {
                Console.Write("General exception: " + ex.Message);
            }

        }
    }
}


