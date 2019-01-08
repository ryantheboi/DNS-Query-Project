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
     *     CNAME - Canonical name (alias) records
     *     SOA - Start of Authority records
     *     AAAA - IPv6 records
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
         * @param classes - the array to store the class
         * @param addresses - the array to store the address
         * @param timeouts - the array to store the timeout to request from authoritative server
         * @param i - the ith resource record that is being parsed
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
         * @param classes - the array to store the class
         * @param addresses - the array to store the canonical (alias) name
         * @param timeouts - the array to store the timeout to request from authoritative server
         * @param i - the ith resource record that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        internal int typeCNAMEParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts,
            StringBuilder[] addresses, int i, int currIdx)
        {
            var c = helper.getClass(r, currIdx);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class

            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length
            var address = new StringBuilder();

            // if CNAME starts as a pointer, use recursive getName function
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
         * @param classes - the array to store the class
         * @param addresses - the array to store the address
         * @param timeouts - the array to store the timeout to request from authoritative server
         * @param i - the ith resource record that is being parsed
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
         * @param classes - the array to store the class
         * @param addresses - the array to store the primary name server
         * @param timeouts - the array to store the timeout to request from authoritative server
         * @param mailbox - the array to store the responsible authority's mailbox
         * @param serialNums - the array to store the serial number
         * @param refreshIntrvls - the array to store the refresh interval, in seconds
         * @param retryIntrvls - the array to store the retry interval, in seconds
         * @param expireLimits - the array to store the expire limit, in seconds
         * @param minTTLs -  the array to store the minimum TTL, in seconds
         * @param i - the ith resource record that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        internal int typeSOAParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts,
            StringBuilder[] addresses, StringBuilder[] mailboxes, StringBuilder[] serialNums,
            StringBuilder[] refreshIntrvls, StringBuilder[] retryIntrvls, StringBuilder[] expireLimits,
            StringBuilder[] minTTLs, int i, int currIdx)
        {
            classes[i] = helper.getClass(r, currIdx);
            currIdx += 2; // to move past the bytes for class

            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length

            // if SOA starts as a pointer, use recursive getName function
            // else, SOA starts with its hex size, use iterative getName function
            var address = new StringBuilder();
            if (r[currIdx].Equals("C0"))
            {
                address = helper.getNamePtr(r, currIdx);
            }
            else
            {
                address = helper.getName(r, currIdx);
            }

            addresses[i] = address;
            // count and skip the space that the primary name server occupies in the packet
            var nameBlock = helper.getNameSize(r, currIdx);
            currIdx += nameBlock[0];
            if (nameBlock[1] == 1) // there is a pointer in the mailbox name, skip the 2 bytes
            {
                currIdx += 2;
            }

            // if SOA starts as a pointer, use recursive getName function
            // else, SOA starts with its hex size, use iterative getName function
            var mailbox = new StringBuilder();
            if (r[currIdx].Equals("C0"))
            {
                mailbox = helper.getNamePtr(r, currIdx);
            }
            else
            {
                mailbox = helper.getName(r, currIdx);
            }

            mailboxes[i] = mailbox;
            // count and skip the space that the responsible authority's mailbox occupies in the packet
            var mailBlock = helper.getNameSize(r, currIdx);
            currIdx += mailBlock[0];
            if (mailBlock[1] == 1) // there is a pointer in the mailbox name, skip the 2 bytes
            {
                currIdx += 2;
            }

            // the following lines grabs the relevant SOA information 4 bytes at a time
            serialNums[i] = helper.getDecimal(r, currIdx, 4);
            currIdx += 4;
            refreshIntrvls[i] = helper.getDecimal(r, currIdx, 4);
            currIdx += 4;
            retryIntrvls[i] = helper.getDecimal(r, currIdx, 4);
            currIdx += 4;
            expireLimits[i] = helper.getDecimal(r, currIdx, 4);
            currIdx += 4;
            minTTLs[i] = helper.getDecimal(r, currIdx, 4);
            currIdx += 4;

            return currIdx;
        }

        /*
         * Helper method for parsing a PTR type response
         * @param r - the string array representation of the response packet
         * @param classes - the array to store the class
         * @param addresses - the array to store the canonical (alias) name
         * @param timeouts - the array to store the timeout to request from authoritative server
         * @param i - the ith resource record that is being parsed
         * @param currIdx - the current ptr location in the packet, r
         * @return - where the ptr was left off in the packet, r
         */
        internal int typePTRParse(string[] r, StringBuilder[] classes, StringBuilder[] timeouts,
            StringBuilder[] addresses, int i, int currIdx)
        {
            var c = helper.getClass(r, currIdx);
            classes[i] = c;
            currIdx += 2; // to move past the bytes for class

            timeouts[i] = helper.getTimeout(r, currIdx);
            currIdx += 6; // to move past the bytes for time to live and data length
            var address = new StringBuilder();

            // if CNAME starts as a pointer, use recursive getName function
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

            return currIdx;
        }
    }
}