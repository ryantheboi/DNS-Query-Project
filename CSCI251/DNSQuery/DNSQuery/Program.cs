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
        private Stopwatch timer;
        private StringBuilder queryTime;

        private StringBuilder timeStamp;
        
        /*
         * Helper method to sent a DNS query to a specified hostname with a DNS server and request type
         * @return timeDate - the date and time the request was made
         */
        public void dnsQuery(string dnsServer, byte[] type, string hostname)
        {
            timeStamp = new StringBuilder();
            timer = new Stopwatch();
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
            
            // send the entire query, record the time it took to send, record the time now
            client.Send(dnsQueryFull, dnsQueryFull.Length);
            
            var dateNow = new StringBuilder();
            var date = DateTime.Now.GetDateTimeFormats()[104];
            date = date.Replace(",", "");
            var tempArr = date.Split(" ");
            var temp = tempArr[1];
            tempArr[1] = tempArr[2];
            tempArr[2] = temp;
            tempArr[3] = "";
            for (int i = 0; i < tempArr.Length; i++)
            {
                dateNow.Append(tempArr[i]);
                if (!tempArr[i].Equals(""))
                {
                    dateNow.Append(" ");
                }
            }
            var year = DateTime.Now.GetDateTimeFormats()[132].Split(" ")[1];
            dateNow.Append(year);
            timeStamp = dateNow;
            
            // receive and parse the response
            answersParse(client, ep, hostname);
                
        }
        
        /*
         * Method for parsing a response that was received after a valid DNS request
         * Also stops the query time measurement as soon as response is received
         * @param client - the UDP client that send the request
         * @param ep - the endpoint that the client is connected to
         * @param hostname - the hostname that was in the request
         * @param queryTime - measure of the total time the query took for request and response
         */
        public void answersParse(UdpClient client, IPEndPoint ep, string hostname)
        {
            byte[] response = client.Receive(ref ep);
            timer.Stop();
            queryTime.Append(timer.ElapsedMilliseconds.ToString());
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

            // to get to the start of the answers section
            var names = new StringBuilder[answers];
            var types = new StringBuilder[answers];
            var classes = new StringBuilder[answers];
            var timeouts = new StringBuilder[answers];
            var addresses = new StringBuilder[answers];
            var currIdx = answersOffset + hostnameOffset + typeClassOffset;
            
            // this loop grabs the next types, classes, and addresses in the response answers
            for (int i = 0; i < answers; i++)
            {
                var name = getNamePtr(r, currIdx);
                names[i] = name;
                currIdx += 2; // to move past the bytes for name pointer
                var typeNum = new StringBuilder();
                typeNum.Append(r[currIdx]);
                typeNum.Append(r[currIdx + 1]);
                var type = getType(typeNum);
                types[i] = type;
                currIdx += 2; // to move past the bytes for type
                
                // the following conditional statements are for parsing the addresses for the request type
                if (type.ToString().Equals("A"))
                {
                    currIdx = typeAParse(r, classes, timeouts, addresses, i, currIdx);
                }
                else if (type.ToString().Equals("CNAME"))
                {
                    currIdx = typeCNAMEParse(r, classes, timeouts, addresses, i, currIdx);
                }
                else if (type.ToString().Equals("AAAA"))
                {
                    currIdx = typeAAAAParse(r, classes, timeouts, addresses, i, currIdx);
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
        }

        /*
         * Helper method for parsing an A type response and the timeout
         * @param r - the string array representation of the response packet
         * @param classes - the array to append the class to
         * @param addresses - the array to append the address to
         * @param timeouts - the array to append the timeout to request from authoritative server to
         * @param i - the ith answer that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        private int typeAParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses, int i, int currIdx)
        {
            var classNum = new StringBuilder();
            classNum.Append(r[currIdx]);
            classNum.Append(r[currIdx + 1]);
            var c = getClass(classNum);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length

            var address = getIPv4Address(r, currIdx);
            addresses[i] = address;
            currIdx += 4; // to move past the bytes for address
            return currIdx;
        }
        
        /*
         * Helper method for parsing a CNAME type response
         * @param r - the string array representation of the response packet
         * @param classes - the array to append the class to
         * @param addresses - the array to append the address to
         * @param timeouts - the array to append the timeout to request from authoritative server to
         * @param i - the ith answer that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        private int typeCNAMEParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses,int i, int currIdx)
        {
            var classNum = new StringBuilder();
            classNum.Append(r[currIdx]);
            classNum.Append(r[currIdx + 1]);
            var c = getClass(classNum);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length
            var address = new StringBuilder();
            
            // if  CNAME starts as a pointer, use recursive getName function
            // else, CNAME starts with its hex size, use iterative getName function
            if (r[currIdx].Equals("C0")) 
            {
                address = getNamePtr(r, currIdx);
            }
            else
            {
                address = getName(r, currIdx);
            }
            addresses[i] = address;
            
            // move to the next value until pointer or null terminator is reached
            while (!r[currIdx].Equals("C0") && !r[currIdx].Equals("00"))
            {
                currIdx++;
            }

            if (r[currIdx].Equals("C0"))
            {
                currIdx += 2; // move past 2 bytes indicating the pointer to hostname
            }

            if (r[currIdx].Equals("00"))
            {
                currIdx += 1; // move past 1 byte indicating the the null terminator
            }
            return currIdx;
        }
        
        /*
         * Helper method for parsing an AAAA type response
         * @param r - the string array representation of the response packet
         * @param classes - the array to append the class to
         * @param addresses - the array to append the address to
         * @param timeouts - the array to append the timeout to request from authoritative server to
         * @param i - the ith answer that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        private int typeAAAAParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses, int i, int currIdx)
        {
            var classNum = new StringBuilder();
            classNum.Append(r[currIdx]);
            classNum.Append(r[currIdx + 1]);
            var c = getClass(classNum);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length

            var address = getIPv6Address(r, currIdx);
            addresses[i] = address;
            currIdx += 16; // to move past the bytes for address
            return currIdx;
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
            headerResponse2.Append(";; flags: qr rd ra; QUERY: ");
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
         * Recursive helper method to get the name from a pointer in the string array packet
         * If a name contains more than one pointer, the pointer is followed recursively
         */
        private StringBuilder getNamePtr(string[] r, int currIdx)
        {
            var fullName = new StringBuilder();
            if (!r[currIdx].Equals("C0"))
            {
                return fullName;
            }
            
            // move past the byte that indicates a pointer and grab the pointer's location in the packet
            currIdx++; 
            var idx = Convert.ToInt32(r[currIdx], 16);
            
            // get name size, move past that byte, then append the entire name to fullName
            var nameSize = Convert.ToInt32(r[idx], 16);
            idx++;
            
            while (nameSize != 0 && nameSize != 192)
            {
                for (var i = 0; i < nameSize; i++)
                {
                    var chDecimal = Convert.ToInt32(r[idx], 16);
                    var ch = (char) chDecimal;
                    fullName.Append(ch);
                    idx++;
                }
                nameSize = Convert.ToInt32(r[idx], 16);
                idx++;
                fullName.Append(".");
            }
            fullName.Append(getNamePtr(r, idx - 1)); // idx - 1 because we moved past the c0

            return fullName;
        }
        
        /*
         * Helper method to get the name from a pointer in the string array packet, currIdx starts at the name size
         * If a name contains more than one pointer, the pointer is followed recursively
         */
        private StringBuilder getName(string[] r, int currIdx)
        {
            var fullName = new StringBuilder();
            
            // get name size, move past that byte, then append the entire name to fullName
            var nameSize = Convert.ToInt32(r[currIdx], 16);
            currIdx++;
            
            var idx = currIdx;
            while (nameSize != 0)
            {
                for (var i = 0; i < nameSize; i++)
                {
                    var chDecimal = Convert.ToInt32(r[idx], 16);
                    var ch = (char) chDecimal;
                    fullName.Append(ch);
                    idx++;
                }
                nameSize = Convert.ToInt32(r[idx], 16);
                idx++;
                fullName.Append(".");

                // if a pointer is seen, follow that pointer in the loop
                if (nameSize == 192)
                {
                    var temp = Convert.ToInt32(r[idx], 16);
                    idx = temp;
                    nameSize = Convert.ToInt32(r[idx], 16);
                    idx++;
                }
            }

            return fullName;
        }
        
        /*
         * Helper method to get the timeout to request from the authoritative server, found in the string array packet.
         * currIdx starts at the location where these 4 bytes are in the packet
         */
        private StringBuilder getTimeout(string[] r, int currIdx)
        {
            var timeoutNum = new StringBuilder();
            timeoutNum.Append(r[currIdx]);
            timeoutNum.Append(r[currIdx + 1]);
            timeoutNum.Append(r[currIdx + 2]);
            timeoutNum.Append(r[currIdx + 3]);
            
            var timeout = new StringBuilder();
            timeout.Append(Convert.ToInt32(timeoutNum.ToString(), 16));
            return timeout;
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
            else // nonexistent domain, or error
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
         * Helper class to get the IPv4 address from where it begins in the packet array
         * IPv4 addresses are 32 bits, so they are 4 bytes long
         * The address is represented as 4 groups, each of decimal representations of 2 hex digits
         * Each group is separated by '.'
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
        
        /*
         * Helper class to get the IPv6 address from where it begins in the packet array
         * IPv6 addresses are 128 bits, so they are 16 bytes long
         * The address is represented as 8 groups of 4 hex digits (or 2 bytes)
         * Each group is separated by ':'
         * An IPv6 address can be any of following forms:
         * 1. all hex digits are lower case
         * 2. leading 0s in a group are omitted, but each group has at least 1 hex digit
         * 3. 1 or more consecutive groups of only 0s can be replaced with 1 empty group as '::'
         */
        private StringBuilder getIPv6Address(string[] r, int currIdx)
        {
            var address = new StringBuilder();
            for (var i = 0; i < 16; i++)
            {
                address.Append(r[currIdx + i]);
                if (i % 2 == 1 && i != 15)
                {
                    address.Append(":");
                }
            }

            // form1 = convert IPv6 address to all lowercase
            var form1 = address.ToString().ToLower();
            
            // form2 = remove trailing 0s, but leave at least 1 hex digit per group
            var form2 = new StringBuilder();
            var tempArr = form1.Split(":");
            for (var i = 0; i < tempArr.Length; i++)
            {
                var temp = tempArr[i];
                if (tempArr[i].Equals("0000"))
                {
                    temp = "0";
                }
                else if (tempArr[i].StartsWith("0"))
                {
                    temp = tempArr[i].TrimStart('0');
                }
                
                form2.Append(temp);
                if (i != tempArr.Length - 1)
                {
                    form2.Append(":");
                }
            }
            address = form2;
            
            // form3 = replace 2+ consecutive groups of 0s with ::
            var form3 = new StringBuilder();
            tempArr = form2.ToString().Split(":");
            var prev0 = false;
            var counter0 = 0;
            for (var i = 0; i < tempArr.Length; i++)
            {
                var temp = tempArr[i];
                if (prev0)
                {
                    if (temp.Equals("0")) // there is a consecutive 0 group
                    {
                        tempArr[i - 1] = "";
                        counter0++;
                    }
                    else // there isn't another 0 group
                    {
                        if (counter0 >= 2){ // there were multiple consecutive 0 groups
                            tempArr[i - 1] = ":";
                            prev0 = false;
                            counter0 = 0;
                        }
                        else // there was only one 0 group
                        {
                            tempArr[i - 1] = "0";
                            prev0 = false;
                            counter0 = 0;
                        }
                    }
                }
                else if (temp.Equals("0"))
                {
                    prev0 = true;
                    counter0++;
                }
            }
            
            for (var i = 0; i < tempArr.Length; i++)
            {
                form3.Append(tempArr[i]);
                if (!tempArr[i].Equals("") && !tempArr[i].Equals(":") && (i != tempArr.Length - 1))
                {
                    form3.Append(":");
                }
            }
            
            address = form3;
            return address;
        }

        /*
         * Helper method to get all the local DNS server addresses
         */
        public List<IPAddress> GetLocalDnsAddress()
        {
            var dnsAddresses = new List<IPAddress>();
   
            NetworkInterface[] adapters  = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                IPAddressCollection dnsServers = adapterProperties.DnsAddresses;
                if (dnsServers.Count > 0)
                {
                    foreach (IPAddress dns in dnsServers)
                    {
                        dnsAddresses.Add(dns.MapToIPv4());
                    }
                }
            }
            return dnsAddresses;
        }
        
        public static void Main(string[] args)
        {
            // Default values: DNS server- the one the OS is set to; Request type- A
            var p = new Program();
            List<IPAddress> dnsServers = p.GetLocalDnsAddress();
            var numDnsServers = dnsServers.Count;
            string dnsServer = dnsServers[0].ToString();
            byte[] type = {0x00, 0x01};
            var hostname = "";
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
                        p.dnsQuery(dnsServer, type, hostname);
                        Console.WriteLine();
                        Console.WriteLine(";; Query time: " + p.queryTime + " msec");
                        Console.WriteLine(";; SERVER: " + dnsServer + "#53(" + dnsServer + ")");
                        Console.WriteLine(";; WHEN: " + p.timeStamp);
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
                    p.dnsQuery(dnsServer, type, hostname);
                    Console.WriteLine();
                    Console.WriteLine(";; Query time: " + p.queryTime + " msec");
                    Console.WriteLine(";; SERVER: " + dnsServer + "#53(" + dnsServer + ")");
                    Console.WriteLine(";; WHEN: " + p.timeStamp);
                }
                catch{}
            }
        }
    }
}
