using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
//using System.Windows.Forms;
using System.Security.Cryptography;

public class SynchronousSocketClient
{
    static byte[] keyAES;
    public static void StartClient()
    {
        // Data buffer for incoming data.
        byte[] bytes;

        // Connect to a remote device.
        try
        {
            // Establish the remote endpoint for the socket.
            // This example uses port 11000 on the local computer.
            IPHostEntry ipHostInfo = Dns.Resolve(Dns.GetHostName());
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

            // Create a TCP/IP  socket.
            Socket sender = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);

            // Connect the socket to the remote endpoint. Catch any errors.
            try
            {
                sender.Connect(remoteEP);

                Console.WriteLine("Socket connected to {0}",
                    sender.RemoteEndPoint.ToString());

                // Encode the data string into a byte array.
                //   byte[] msg = Encoding.ASCII.GetBytes("This is a test<EOF>");

                // Send the data through the socket.
                // int bytesSent = sender.Send(msg);

                // Receive the response from the remote device.

                string data = null;
                bytes = new byte[16000];
                while (true)
                {
                    int bytesCount = sender.Receive(bytes);
                    
                    
                    //answer = bytes;
                    data = Encoding.ASCII.GetString(bytes);
                    if (data.IndexOf("{Key}") > -1)
                    {
                        byte[] answer = new byte[256];
                        for (int i = 0; i < 256; i++)
                            answer[i] = bytes[i + 5];
                        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                        rsa.FromXmlString(File.ReadAllText("c:\\private.txt"));
                        keyAES = rsa.Decrypt(answer, false);
                        byte[] buff = Encoding.UTF8.GetBytes("Ключ был успешно получен!");
                        sender.Send(buff);
                        Console.Write("Сессионный ключ был успешно получен\n");
                        data = null;
                        bytesCount = sender.Receive(bytes);


                        //answer = bytes;
                        data = Encoding.ASCII.GetString(bytes);

                    }
                    if (data!=null)
                    {

                        byte[] encMes = new byte[bytesCount];
                        Array.Copy(bytes, 0, encMes, 0, bytesCount);
                        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                        aes.KeySize = 256;
                        aes.Key = keyAES;
                        //aes.Padding = PaddingMode.Zeros;
                        byte[] iv = new byte[16];
                        aes.IV = iv;
                        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                        // Create the streams used for decryption. 
                        string plaintext;
                        using (MemoryStream msDecrypt = new MemoryStream(encMes))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {

                                    // Read the decrypted bytes from the decrypting stream 
                                    // and place them in a string.
                                    plaintext = srDecrypt.ReadToEnd();
                                    File.WriteAllText("c:\\result", plaintext);
                                    Console.WriteLine("Расшифрованный принятый файл : {0}", plaintext);
                                }
                            }
                        }
                        break;
                    }
                }
                
                Console.Read();
                // Release the socket.
                sender.Shutdown(SocketShutdown.Both);
                sender.Close();

            }


            catch (ArgumentNullException ane)
            {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }

        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }
    }

    

    public static int Main(String[] args)
    {
        StartClient();
        return 0;
    }
}