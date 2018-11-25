using System;
using System.ComponentModel.Design;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Text;

namespace ConsoleApplication
{
    public class Program
    {
        public void cnameType(string hostname)
        {
            var client = new UdpClient();
            IPEndPoint ep = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);
            client.Connect(ep);

            // the 12 byte header
            byte[] transactionID = {0x2a, 0x9c};
            byte[] flags = {0x01, 0x20};
            byte[] header = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            // the host name and domain, including their lengths, terminated by null byte
            byte[] cnameLength = new byte[1];
            byte[] hostnameLength = new byte[1];
            byte[] domainLength = new byte[1];
            byte[] cnameBytes = Encoding.Default.GetBytes((hostname.Split('.')[0]));
            byte[] hostnameBytes = Encoding.Default.GetBytes(hostname.Split('.')[1]);
            byte[] domainBytes = Encoding.Default.GetBytes(hostname.Split('.')[2]);
            cnameLength[0] = (byte) cnameBytes.Length;
            hostnameLength[0] = (byte) hostnameBytes.Length;
            domainLength[0] = (byte) domainBytes.Length;
            byte[] nullTerminate = {0x00};

            // A type record and Class IN
            byte[] typeA = {0x00, 0x01};
            byte[] classIN = {0x00, 0x01};

            // Concatenate every byte into DNS Query
            byte[] dnsQuery = transactionID.Concat(flags)
                                           .Concat(header)
                                           .Concat(cnameLength)
                                           .Concat(cnameBytes)
                                           .Concat(hostnameLength)
                                           .Concat(hostnameBytes)
                                           .Concat(domainLength)
                                           .Concat(domainBytes)
                                           .Concat(nullTerminate)
                                           .Concat(typeA)
                                           .Concat(classIN)
                                           .ToArray();
            client.Send(dnsQuery, dnsQuery.Length);

            byte[] response = client.Receive(ref ep);
            var responseHex = BitConverter.ToString(response);
            var r = responseHex.Split("-");
            Console.WriteLine(";; Got answer:");

            // initial print of the info in the 12 byte header
            printHeader(r);

            // to get the type
            var hostnameOffset = cnameLength[0] + hostnameLength[0] + domainLength[0] + 4;
            var typeClassOffset = 4;
            var ptrOffset = 2;
            var typeOffset = hostnameOffset + typeClassOffset + ptrOffset;
            var typeNum = new StringBuilder();
            typeNum.Append(r[12 + typeOffset]);
            typeNum.Append(r[12 + typeOffset + 1]);
            var type = getType(typeNum);

            // to get the class (it should be IN for internet)
            var classOffset = typeOffset + 2;
            var classNum = new StringBuilder();
            classNum.Append(r[12 + classOffset]);
            classNum.Append(r[12 + classOffset + 1]);
            var c = getClass(classNum);

            var currIdx = 12 + classOffset + 2;
            Console.WriteLine(r[currIdx] + " " + currIdx);
            
            // to get the address
            var classLiveDataOffset = 8;
            var answerOffset = classOffset + classLiveDataOffset;
            var cnameOffset = Convert.ToInt32(r[12 + answerOffset], 16); // the length of the CNAME
            cnameOffset += 2; // to move to the pointer to hostname
            var nameOffset = answerOffset + cnameOffset;
            var nameLoc = Convert.ToInt32(r[12 + nameOffset], 16); // ***************where the unaliased hostname begins

            var addressOffset = nameOffset + 13; // to move to the address

            Console.WriteLine(r[addressOffset + 12]);
            var address = new StringBuilder();
            for (var i = 0; i < 4; i++)
            {
                address.Append(Convert.ToInt32(r[12 + addressOffset + i], 16));
                if (i != 3)
                {
                    address.Append(".");
                }
            }

            Console.WriteLine(address);
        }

        public void aType(UdpClient client, IPEndPoint ep, string hostname)
        {
            byte[] response = client.Receive(ref ep);
            Console.WriteLine(";; Got answer:");
            
            var responseHex = BitConverter.ToString(response);
            var r = responseHex.Split("-");
            
            // initial print of the info in the 12 byte header
            printHeader(r);

            // get the number of answers in the response
            var answers = getAnswers(r);
            
            // to move past the queries section
            var answersOffset = 12; 
            var hostnameOffset = hostname.Length + 2;
            var typeClassOffset = 4;
            var ptrOffset = 2;

            // to get to the start of the answers section
            var types = new StringBuilder[answers];
            var classes = new StringBuilder[answers];
            var addresses = new StringBuilder[answers];
            var currIdx = answersOffset + hostnameOffset + typeClassOffset + ptrOffset;
            
            // this loop grabs the next types, classes, and addresses in the response answers
            for (int i = 0; i < answers; i++)
            {
                var typeNum = new StringBuilder();
                typeNum.Append(r[currIdx]);
                typeNum.Append(r[currIdx + 1]);
                var type = getType(typeNum);
                types[i] = type;
                currIdx += 2; // to move past the bytes for type

                var classNum = new StringBuilder();
                classNum.Append(r[currIdx]);
                classNum.Append(r[currIdx + 1]);
                var c = getClass(classNum);
                classes[i] = c;
                currIdx += 2; // to move past the bytes for class
                currIdx += 6; // to move past the bytes for time to live and data length

                var address = getIPv4Address(r, currIdx);
                addresses[i] = address;
                currIdx += 4; // to move past the bytes for address
                currIdx += ptrOffset;
            }

            // final printout for answers section
            Console.WriteLine();
            Console.WriteLine(";; ANSWER SECTION:");
            for (int i = 0; i < answers; i++)
            {
                var result = new StringBuilder();
                result.Append(hostname + ". 0 ");
                result.Append(classes[i] + " ");
                result.Append(types[i] + " ");
                result.Append(addresses[i]);
                Console.WriteLine(result);
            }
        }

        /*
         * Helper method to sent a DNS query to a specified hostname with a DNS server and request type
         */
        public IPEndPoint dnsQuery(string dnsServer, byte[] type, string hostname)
        {
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
            
            // send the entire query and return the endpoint to be received
            client.Send(dnsQueryFull, dnsQueryFull.Length);

            aType(client, ep, hostname);
                
            return ep;
        }
        
        /*
         * Helper method to print out the 12 byte header information
         */
        private void printHeader(string[] r)
        {
            // first print out information from 12 byte header
            // to get opcode, status, and id
            var headerResponse1 = new StringBuilder();
            var transIDNum = new StringBuilder();
            transIDNum.Append(r[0]);
            transIDNum.Append(r[1]);
            var transID = getID(transIDNum);
            var statusNum = new StringBuilder();
            statusNum.Append(r[2]);
            statusNum.Append(r[3]);
            var status = getStatus(statusNum);
            headerResponse1.Append(";; ->>HEADER<<- opcode: QUERY, status: ");
            headerResponse1.Append(status + ", id: ");
            headerResponse1.Append(transID);
            Console.WriteLine(headerResponse1);
            
            // to get questions, answer RRs, authority RRs, additional RRs
            var headerResponse2 = new StringBuilder();
            var questionsNum = new StringBuilder();
            questionsNum.Append(r[4]);
            questionsNum.Append(r[5]);
            var questions = Convert.ToInt32(questionsNum.ToString(), 16);
            var answersNum = new StringBuilder();
            answersNum.Append(r[6]);
            answersNum.Append(r[7]);
            var answers = Convert.ToInt32(answersNum.ToString(), 16);
            var authorityNum = new StringBuilder();
            authorityNum.Append(r[8]);
            authorityNum.Append(r[9]);
            var authority = Convert.ToInt32(authorityNum.ToString(), 16);
            var additionalNum = new StringBuilder();
            additionalNum.Append(r[10]);
            additionalNum.Append(r[11]);
            var additional = Convert.ToInt32(additionalNum.ToString(), 16);
            headerResponse2.Append(";; flags: qr rd rq; QUERY: ");
            headerResponse2.Append(questions + ", ANSWER: ");
            headerResponse2.Append(answers + ", AUTHORITY: ");
            headerResponse2.Append(authority + ", ADDITIONAL: ");
            headerResponse2.Append(additional);
            Console.WriteLine(headerResponse2);
        }

        /*
         * Helper method to get the number of answers from the response
         */
        private int getAnswers(string[] r)
        {
            var answersNum = new StringBuilder();
            answersNum.Append(r[6]);
            answersNum.Append(r[7]);
            var answers = Convert.ToInt32(answersNum.ToString(), 16);
            return answers;
        }
        
        /*
         * Helper method to get the transaction ID from its 2 byte representation
         */
        private StringBuilder getID(StringBuilder transIDNum)
        {
            var transID = new StringBuilder();
            transID.Append(Convert.ToInt32(transIDNum.ToString(), 16));
            return transID;
        }
        
        /*
         * Helper method to get the query status from its 2 byte representation
         */
        private StringBuilder getStatus(StringBuilder statusNum)
        {
            var status = new StringBuilder();
            if (statusNum.ToString().Equals("8180"))
            {
                status.Append("NOERROR");
            }
            else
            {
                status.Append("ERROR");
            }
            return status;
        }
        
        /*
         * Helper method to get the type from its 2 byte representation
         */
        private StringBuilder getType(StringBuilder typeNum)
        {
            var type = new StringBuilder();
            if (typeNum.ToString().Equals("0005"))
            {
                type.Append("CNAME");
            }
            else if (typeNum.ToString().Equals("001C"))
            {
                type.Append("AAAA");
            }
            else if (typeNum.ToString().Equals("0001"))
            {
                type.Append("A");
            }

            return type;
        }

        /*
         * Helper method to get the class from its 2 byte representation
         */
        private StringBuilder getClass(StringBuilder classNum)
        {
            var c = new StringBuilder();
            if (classNum.ToString().Equals("0001"))
            {
                c.Append("IN");
            }
            else
            {
                c.Append("N/A");
            }

            return c;
        }

        /*
         * Helper class to get the IPv4 address from where it begins in the array
         */
        private StringBuilder getIPv4Address(string[] r, int currIdx)
        {
            var address = new StringBuilder();
            for (var i = 0; i < 4; i++)
            {
                address.Append(Convert.ToInt32(r[currIdx + i], 16));
                if (i != 3)
                {
                    address.Append(".");
                }
            }
            return address;
        }

    public static void Main(string[] args)
        {
            var p = new Program();
            //p.aType("snapchat.com");
            //p.cnameType("www.rit.edu");
            byte[] type = {0x00, 0x01};
            p.dnsQuery("8.8.8.8", type, "snapchat.com");

        }
    }
}
