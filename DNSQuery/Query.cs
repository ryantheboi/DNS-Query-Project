using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace ConsoleApplication
{
    /*
     * @ author - Ryan Chung
     * This class is responsible for the entire DNS query
     * A request is first sent out to a DNS server asking for a hostname
     * If a response is received, then it gets parsed here
     */
    public class Query
    {
        private Helpers helper;
        private Parser parser;
        private Stopwatch timer;
        private String queryTime;
        private String timeStamp;

        /* Constructor to initialize the Query object */
        public Query()
        {
            this.helper = new Helpers();
            this.parser = new Parser();
            this.timer = new Stopwatch();
        }
        
        /*
         * Helper method to sent a DNS query to a specified hostname with a DNS server and request type
         * @return timeDate - the date and time the request was made
         */
        public void SendRequest(string dnsServer, byte[] type, string hostname)
        {
            timer.Start();
            
            var client = new UdpClient();
            IPEndPoint ep = new IPEndPoint(IPAddress.Parse(dnsServer), 53);
            client.Connect(ep);

            // the 12 byte header
            byte[] transactionID = {0x2a, 0x9c};
            byte[] flags = {0x01, 0x20};
            byte[] header = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            // concatenate with the host name and domain, including their lengths, terminated by null byte
            var hostnameSplit = hostname.Split(".");
            byte[] dnsQueryFull = transactionID.Concat(flags).Concat(header).ToArray();
            foreach (var hostnamePart in hostnameSplit)
            {
                byte[] hostnamePartLength = new byte[1];
                byte[] hostnamePartBytes = Encoding.Default.GetBytes(hostnamePart);
                hostnamePartLength[0] = (byte)hostnamePartBytes.Length;
                dnsQueryFull = dnsQueryFull.Concat(hostnamePartLength).Concat(hostnamePartBytes).ToArray();
            }
            byte[] nullTerminate = {0x00};
            dnsQueryFull = dnsQueryFull.Concat(nullTerminate).ToArray();

            // concatenate type record and Class IN
            byte[] classIN = {0x00, 0x01};
            dnsQueryFull = dnsQueryFull.Concat(type).Concat(classIN).ToArray();
            
            // send the entire query and record the time now
            client.Send(dnsQueryFull, dnsQueryFull.Length);
            timeStamp = DateTime.Now.ToString("ddd MMM dd HH':'mm':'ss 'GMT' yyyy");

            // receive and parse the response
            ResponseParse(client, ep, hostname);
        }
        
        /*
         * Method for parsing a response that was received after a valid DNS request
         * Also stops the query time measurement as soon as response is received
         * @param client - the UDP client that send the request
         * @param ep - the endpoint that the client is connected to
         * @param hostname - the hostname that was in the request
         * @param queryTime - measure of the total time the query took for request and response
         */
        private void ResponseParse(UdpClient client, IPEndPoint ep, string hostname)
        {
            byte[] response = client.Receive(ref ep);
            timer.Stop();
            queryTime = timer.ElapsedMilliseconds.ToString();
         
            Console.WriteLine(";; Got answer:");
            var responseHex = BitConverter.ToString(response);
            var r = responseHex.Split("-");
            
            // initialize helper obj and print the info in the 12 byte header
            
            helper.printHeader(r);
            

            // get the number of answer, authority, and additional resource records in response
            var answers = helper.getAnswers(r);
            var authorityRRs = helper.getAuthorityRRs(r);
            var additionalRRs = helper.getAdditionalRRs(r);
            
            // to move past the queries section
            var answersOffset = 12; 
            var hostnameOffset = hostname.Length + 2;
            var typeClassOffset = 4;

            // initialize the list f names, types, classes, TTLs, and addresses for every answer
            var resourceRecords = answers + authorityRRs + additionalRRs;
            var names = new StringBuilder[resourceRecords];
            var types = new StringBuilder[resourceRecords];
            var classes = new StringBuilder[resourceRecords];
            var timeouts = new StringBuilder[resourceRecords];
            var addresses = new StringBuilder[resourceRecords];
            
            // to skip the questions section and get to the start of the answers section
            var currIdx = answersOffset + hostnameOffset + typeClassOffset;
            
            // this loop grabs the next types, classes, and addresses in the response answers
            for (int i = 0; i < answers; i++)
            {
                var name = helper.getNamePtr(r, currIdx);
                names[i] = name;
                currIdx += 2; // to move past the bytes for name pointer
                
                var type = helper.getType(r, currIdx);
                types[i] = type;
                currIdx += 2; // to move past the bytes for type
                
                // the following switch cases are for parsing the addresses for the request type
                switch (type.ToString())
                {
                    case "A":
                        currIdx = parser.typeAParse(r, classes, timeouts, addresses, i, currIdx);
                        break;
                    case "CNAME":
                        currIdx = parser.typeCNAMEParse(r, classes, timeouts, addresses, i, currIdx);
                        break;
                    case "SOA":
                        currIdx = parser.typeSOAParse(r, classes, timeouts, addresses, i, currIdx);
                        break;
                    case "AAAA":
                        currIdx = parser.typeAAAAParse(r, classes, timeouts, addresses, i, currIdx);
                        break;
                }
            }

            // final printout for answers section, if there are answers
            if (answers > 0)
            {
                Console.WriteLine();
                Console.WriteLine(";; ANSWER SECTION:");
                for (int i = 0; i < answers; i++)
                {
                    var result = new StringBuilder();
                    result.AppendFormat( "{0, -24} {1, -8} {2, -8} {3, -8} {4}", 
                        names[i], timeouts[i], classes[i], types[i], addresses[i]);
                    
                    Console.WriteLine(result);
                }
            }

            if (authorityRRs > 0)
            {
                Console.WriteLine();
                Console.WriteLine(";; AUTHORITY SECTION:");
                for (int i = 0; i < authorityRRs; i++)
                {
                    var result = new StringBuilder();
                    result.AppendFormat( "{0, -24} {1, -8} {2, -8} {3, -8} {4}", 
                        names[i], timeouts[i], classes[i], types[i], addresses[i]);
                    
                    Console.WriteLine(result);
                }
            }
            
            if (additionalRRs > 0)
            {
                Console.WriteLine();
                Console.WriteLine(";; ADDITIONAL SECTION:");
                for (int i = 0; i < additionalRRs; i++)
                {
                    var result = new StringBuilder();
                    result.AppendFormat( "{0, -24} {1, -8} {2, -8} {3, -8} {4}", 
                        names[i], timeouts[i], classes[i], types[i], addresses[i]);
                    
                    Console.WriteLine(result);
                }
            }
        }
        
        /*
         * Returns the time that it took to send the request and receive a response
         */
        public String getQueryTime()
        {
            return this.queryTime;
        }
        
        /*
         * Returns the date and time that the query was made
         */
        public String getTimeStamp()
        {
            return this.timeStamp;
        }
    }
}