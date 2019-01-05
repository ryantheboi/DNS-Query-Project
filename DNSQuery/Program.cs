using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

/*
 * @author - Ryan Chung
 * This program sends DNS queries and parses the response back
 * Currently is capable of sending A and AAAA requests
 * Currently is capable of parsing A, AAAA, and CNAME type responses
 */
namespace ConsoleApplication
{
    public class Program
    {
        public static void Main()
        {
            // Default values: DNS server- the one the OS is set to; Request type- A
            var helper = new Helpers();
            var query = new Query();
            List<IPAddress> dnsServers = helper.GetLocalDnsAddresses();
            foreach (var i in dnsServers)
            {
                Console.WriteLine(i);
            }
            var numDnsServers = dnsServers.Count;
            string dnsServer = dnsServers[0].ToString();
            
            Console.WriteLine("Usage: dotnet run [DNS Server] [Request Type] [Hostname]");
            Console.WriteLine("Enter 'exit' to exit program");
            var input = Console.ReadLine();
            while (!input.Equals("exit"))
            {
                byte[] type = {0x00, 0x01};
                var hostname = "";
                
                var args = input.Split(" ");
                if (args.Length == 3)
                {
                    dnsServer = args[0];
                    if (args[1].Equals("AAAA"))
                    {
                        type[1] = 0x1c;
                    }

                    hostname = args[2];
                }
                else if (args.Length == 2)
                {
                    if (args[0].Equals("AAAA"))
                    {
                        type[1] = 0x1c;
                    }

                    hostname = args[1];
                }
                else if (args.Length == 1)
                {
                    hostname = args[0];
                }

                // try to make the DNS query and return the time it took & time it occurred
                // if there was no dns server provided in args, use the first local one that works
                if (args.Length != 3)
                {
                    int num = 0;
                    string exception = "exp";
                    while (!exception.Equals("") && num < numDnsServers)
                    {
                        try
                        {
                            dnsServer = dnsServers[num].ToString();
                            query.SendRequest(dnsServer, type, hostname);
                            Console.WriteLine();
                            Console.WriteLine(";; Query time: " + query.getQueryTime() + " msec");
                            Console.WriteLine(";; SERVER: " + dnsServer + "#53(" + dnsServer + ")");
                            Console.WriteLine(";; WHEN: " + query.getTimeStamp());
                            exception = ""; // working dns server found, break out of loop
                            break;
                        }
                        catch (Exception ex)
                        {
                            num++;
                            exception = ex.ToString();
                        }
                    }

                    if (num == numDnsServers)
                    {
                        Console.WriteLine("No local DNS servers found.  Please specify one.");
                    }
                }

                else
                {

                    try
                    {
                        query.SendRequest(dnsServer, type, hostname);
                        Console.WriteLine();
                        Console.WriteLine(";; Query time: " + query.getQueryTime() + " msec");
                        Console.WriteLine(";; SERVER: " + dnsServer + "#53(" + dnsServer + ")");
                        Console.WriteLine(";; WHEN: " + query.getTimeStamp());
                    }
                    catch
                    {
                    }
                }

                Console.WriteLine();
                input = Console.ReadLine();
            }
        }
    }
}
