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
     * @author - Ryan Chung
     * This class contains methods to extract and translate the information from a network packet
     * The class can extract the following from a packet:
     *     The 12 byte packet header
     *     The number of answers in the response
     *     The domain name
     *     The time to live
     *     The query status
     *     The transaction ID
     *     The DNS record type
     *     The class (usually IN for internet)
     *     The IPv4 or IPv6 address(es)
     *     The number of bytes that a name occupies in a packet
     * The class can also perform special features for specific commands such as:
     *     -x reverses the IP address and appends '.in-addr.arpa' if IPv4, '.ip6.arpa' if IPv6
     */
    public class Helpers
    {
        /*
         * Helper method to print out the 12 byte header information
         */
        internal void printHeader(string[] r)
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
        internal int getAnswers(string[] r)
        {
            var answersNum = new StringBuilder();
            answersNum.Append(r[6]);
            answersNum.Append(r[7]);
            var answers = Convert.ToInt32(answersNum.ToString(), 16);
            return answers;
        }
        
        /*
         * Helper method to get the number of authority resource records from the response
         */
        internal int getAuthorityRRs(string[] r)
        {
            var authorityRRsNum = new StringBuilder();
            authorityRRsNum.Append(r[8]);
            authorityRRsNum.Append(r[9]);
            var authorityRRs = Convert.ToInt32(authorityRRsNum.ToString(), 16);
            return authorityRRs;
        }
        
        /*
         * Helper method to get the number of authority resource records from the response
         */
        internal int getAdditionalRRs(string[] r)
        {
            var additionalRRsNum = new StringBuilder();
            additionalRRsNum.Append(r[10]);
            additionalRRsNum.Append(r[11]);
            var additionalRRs = Convert.ToInt32(additionalRRsNum.ToString(), 16);
            return additionalRRs;
        }
        
        /*
         * Recursive helper method to get the name from a pointer in the string array packet
         * If a name contains more than one pointer, the pointer is followed recursively
         */
        internal StringBuilder getNamePtr(string[] r, int currIdx)
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
         * If a name contains more than one pointer, the pointer is followed iteratively
         */
        internal StringBuilder getName(string[] r, int currIdx)
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
         * Helper method to count the number of bytes that a name occupies in the string array packet,
         * inherently includes the null terminator in counting, currIdx starts at the name size
         * Counting stops if a null terminator or a pointer is encountered
         * @return sizeBlock - an array of ints to store the following info about a name:
         *         sizeBlock[0] - the size of the name up until a pointer, if one exists
         *         sizeBlock[1] - 0 by default if there is no pointer in the name, 1 if there is
         */
        internal int[] getNameSize(string[] r, int currIdx)
        {
            var sizeBlock = new int[2];
            var totalSize = 0;
            var hasPointer = 0;
            var idx = currIdx;
            
            // check if the name starts with a pointer
            if (r[idx].Equals("C0"))
            {
                hasPointer = 1;
                sizeBlock[0] = totalSize;
                sizeBlock[1] = hasPointer;
                return sizeBlock;
            }
            
            // get name size, append to running total, move past that byte
            var nameSize = Convert.ToInt32(r[idx], 16);
            totalSize += nameSize;
            totalSize++;
            idx++;
            while (nameSize != 0 && nameSize != 192)
            {
                idx += nameSize;
                nameSize = Convert.ToInt32(r[idx], 16);
                if (nameSize == 192)
                {
                    hasPointer = 1;
                    break;
                }
                totalSize += nameSize;
                totalSize++; // if nameSize is 1, increment by 1 for the null terminator
                idx++;
            }
            sizeBlock[0] = totalSize;
            sizeBlock[1] = hasPointer;
            return sizeBlock;
        }
        
        /*
         * Helper method to get the timeout to request from the authoritative server, found in the string array packet.
         * currIdx starts at the location where these 4 bytes are in the packet
         */
        internal StringBuilder getTimeout(string[] r, int currIdx)
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
         * Helper method to get the query status from its 2 byte representation
         */
        
        internal StringBuilder getStatus(StringBuilder statusNum)
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
         * Helper method to get the transaction ID from its 2 byte representation
         */
        private StringBuilder getID(StringBuilder transIDNum)
        {
            var transID = new StringBuilder();
            transID.Append(Convert.ToInt32(transIDNum.ToString(), 16));
            return transID;
        }
        
        /*
         * Helper method to get the type from its 2 byte representation, found in the string array packet.
         * currIdx starts at the location where these 4 bytes are in the packet
         */
        internal StringBuilder getType(string[] r, int currIdx)
        {
            var typeNum = new StringBuilder();
            typeNum.Append(r[currIdx]);
            typeNum.Append(r[currIdx + 1]);
            
            var type = new StringBuilder();
            switch (typeNum.ToString())
            {
                case "0001":
                    type.Append("A");
                    break;
                case "0002":
                    type.Append("NS");
                    break;
                case "0005":
                    type.Append("CNAME");
                    break;
                case "0006":
                    type.Append("SOA");
                    break;
                case "000C":
                    type.Append("PTR");
                    break;
                case "000F":
                    type.Append("MX");
                    break;
                case "001C":
                    type.Append("AAAA");
                    break;
            }
            return type;
        }

        /*
         * Helper method to get the class from its 2 byte representation, found in the string array packet.
         * currIdx starts at the location where these 4 bytes are in the packet
         */
        internal StringBuilder getClass(string[] r, int currIdx)
        {
            var classNum = new StringBuilder();
            classNum.Append(r[currIdx]);
            classNum.Append(r[currIdx + 1]);
            
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
         * Helper method to get the decimal representation of a variable number of consecutive bytes in
         * a network packet.
         * @param r - the string array representation of a network packet
         * @param currIdx - index that starts at the location of interest.
         * @param numBytes - the number of bytes to look at past currIdx in r
         * @return - the decimal representation of the bytes of interest
         */
        internal StringBuilder getDecimal(string[] r, int currIdx, int numBytes)
        {
            var hexNum = new StringBuilder();
            var idx = currIdx;
            for (var i = 0; i < numBytes; i++)
            {
                hexNum.Append(r[idx]);
                idx++;
            }

            var dec = new StringBuilder();
            dec.Append(Convert.ToInt32(hexNum.ToString(), 16));
            return dec;
        }
        
        /*
         * Helper method to get the IPv4 address from where it begins in the packet array
         * IPv4 addresses are 32 bits, so they are 4 bytes long
         * The address is represented as 4 groups, each of decimal representations of 2 hex digits
         * Each group is separated by '.'
         */
        internal StringBuilder getIPv4Address(string[] r, int currIdx)
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
         * Helper method to get the IPv6 address from where it begins in the packet array
         * IPv6 addresses are 128 bits, so they are 16 bytes long
         * The address is represented as 8 groups of 4 hex digits (or 2 bytes)
         * Each group is separated by ':'
         * An IPv6 address can be any of following forms:
         * 1. all hex digits are lower case
         * 2. leading 0s in a group are omitted, but each group has at least 1 hex digit
         * 3. 1 or more consecutive groups of only 0s can be replaced with 1 empty group as '::'
         */
        internal StringBuilder getIPv6Address(string[] r, int currIdx)
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
        internal List<IPAddress> GetLocalDnsAddresses()
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

        /*
         * Helper method to conveniently reverse an IP address for the -x (PTR record) query.
         * For IPv4 addresses the order of the bytes are reversed and '.in-addr.arpa' is appended.
         * For IPv6 addresses, the full IPv6 address is reversed, with each hex digit separated by a '.'
         * and '.ip6.arpa' is appended.
         * 
         */
        internal String reverseDNS(String ipAddress)
        {
            var reversed = new StringBuilder();
            
            // reverse IPv6 address and append .ip6.arpa
            if (ipAddress.Contains(":"))
            {
                // initialize the 8 groups for the address to be split by
                var groups = new StringBuilder[8];
                for (var i = 0; i < 8; i++)
                {
                    groups[i] = new StringBuilder();
                }
                // split the IPv6 address into groups, of at most 4 hex digits ea, by the colon(s)
                var groupNum = 0;
                var hasColon = 0;
                foreach(var ch in ipAddress)
                {
                    if (ch == ':')
                    {
                        if (hasColon == 1)
                        {
                            groups[groupNum].Append(':');
                        }
                        groupNum++;
                        hasColon = 1;
                    }
                    else
                    {
                        groups[groupNum].Append(ch);
                        hasColon = 0;
                    }
                }
                // reconstruct the full IPv6 address, w/ every hex digit not separated by anything
                var reconstruct = new StringBuilder();
                foreach (var group in groups)
                {
                    if (!group.Equals(""))
                    {
                        // if there is a double colon, append every zero group that is covered there
                        if (group[0] == ':')
                        {
                            var zeroGroups = 8 - groupNum;
                            for (var i = 0; i < zeroGroups; i++)
                            {
                                reconstruct.Append("0000");
                            }
                        }
                        else
                        {
                            // append current group to the reconstruction, including leading 0s if any
                            var count = group.Length;
                            var zeroCount = 4 - count;
                            for (var i = 0; i < zeroCount; i++)
                            {
                                reconstruct.Append("0");
                            }

                            for (var i = 0; i < count; i++)
                            {
                                reconstruct.Append(group[i]);
                            }
                        }
                    }
                }
                // reverse the reconstructed IPv6 address, separate each hex digit with '0', append '.ip6.arpa'
                for(var i = 32; i >= 0; i--)
                {
                    try
                    {
                        reversed.Append(reconstruct[i]);
                        reversed.Append('.');
                    }
                    catch{}
                }
                reversed.Append("ip6.arpa");
            }
            
            // reverse IPv4 address and append .in-addr.arpa
            else
            {
                var ipArray = ipAddress.Split(".");
                var n = ipArray.Length;
                for (var i = n-1; i >= 0; i--)
                {
                    reversed.Append(ipArray[i]);
                    reversed.Append(".");
                }
                reversed.Append("in-addr.arpa");
            }

            return reversed.ToString();
        }
    }
}