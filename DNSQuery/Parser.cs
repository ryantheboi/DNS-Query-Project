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
     * This class contains methods to parse the different DNS record type responses that may be received
     * Currently, the following DNS record types in a response can be parsed:
     *     A - IPv4 records
     *     AAAA - IPv6 records
     *     CNAME - Canonical name (alias) records
     */
    public class Parser
    {
        private Helpers helper;
        
        /* Constructor to initialize the Parser object */
        public Parser()
        {
            this.helper = new Helpers();
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
        internal int typeAParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses, int i, int currIdx)
        {
            
            var c = helper.getClass(r, currIdx);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length

            var address = helper.getIPv4Address(r, currIdx);
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
        internal int typeCNAMEParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses,int i, int currIdx)
        {
            var c = helper.getClass(r, currIdx);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length
            var address = new StringBuilder();
            
            // if  CNAME starts as a pointer, use recursive getName function
            // else, CNAME starts with its hex size, use iterative getName function
            if (r[currIdx].Equals("C0")) 
            {
                address = helper.getNamePtr(r, currIdx);
            }
            else
            {
                address = helper.getName(r, currIdx);
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
        internal int typeAAAAParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses, int i, int currIdx)
        {
            var c = helper.getClass(r, currIdx);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length

            var address = helper.getIPv6Address(r, currIdx);
            addresses[i] = address;
            currIdx += 16; // to move past the bytes for address
            return currIdx;
        }
        
        /*
         * Helper method for parsing an SOA type response
         * @param r - the string array representation of the response packet
         * @param classes - the array to append the class to
         * @param addresses - the array to append the address to
         * @param timeouts - the array to append the timeout to request from authoritative server to
         * @param i - the ith answer that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        internal int typeSOAParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts, 
            StringBuilder[] addresses, int i, int currIdx)
        {
            var c = helper.getClass(r, currIdx);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class
            
            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length

            var address = new StringBuilder();
            // if  SOA starts as a pointer, use recursive getName function
            // else, SOA starts with its hex size, use iterative getName function
            if (r[currIdx].Equals("C0")) 
            {
                address = helper.getNamePtr(r, currIdx);
            }
            else
            {
                address = helper.getName(r, currIdx);
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
    }
}