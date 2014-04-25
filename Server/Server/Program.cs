using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Threading;


public class SynchronousSocketListener
{

    // Incoming data from the client.
    public static string data = null;

    public static void StartListening()
    {
        // Data buffer for incoming data.
        byte[] bytes = new Byte[16000];

        IPHostEntry ipHostInfo = Dns.Resolve(Dns.GetHostName());
        IPAddress ipAddress = ipHostInfo.AddressList[0];
        IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

        // Create a TCP/IP socket.
        Socket listener = new Socket(AddressFamily.InterNetwork,
            SocketType.Stream, ProtocolType.Tcp);
        Console.Write("\"gen\" - Генерировать RSA ключи\n\"enc\" - Выбрать файл для шифрования и отправки\n");
       // Console.ReadLine();
        string answer = null;
        byte[] aesKey = null;
        answer = Console.ReadLine();
        if (answer == "gen")
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            string rsaKey = rsa.ToXmlString(true);
            File.WriteAllText("c:\\private.txt", rsaKey);
            Console.Write("Ключи RSA были успешно сгенерированы и сохранены.\n\n");            
        }
        Console.Write("\"gen\" - Генерировать RSA ключи\n\"enc\" - Выбрать файл для шифрования и отправки\n");
        answer = Console.ReadLine();
        if (answer == "enc")
        {
            // Bind the socket to the local endpoint and 
            // listen for incoming connections.
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                // Start listening for connections.
                while (true)
                {
                    Console.WriteLine("Ожидание соединения...");
                    // Program is suspended while waiting for an incoming connection.
                    Socket handler = listener.Accept();
                    data = null;
                    Console.Write("Нажмите Enter, чтобы выбрать файл для отправки");
                    Console.Read();
                    OpenFileDialog dlg = new OpenFileDialog();
                    dlg.AddExtension = true;
                    if (dlg.ShowDialog() == DialogResult.OK)
                    {
                        using (AesCryptoServiceProvider myAes = new AesCryptoServiceProvider())
                        {
                            myAes.KeySize = 256;
                            myAes.GenerateKey();
                           // myAes.Padding = PaddingMode.None;
                            aesKey = myAes.Key;
                            Console.WriteLine(dlg.FileName);
                            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                            rsa.FromXmlString(File.ReadAllText("c:\\private.txt"));
                            byte[] df = rsa.Encrypt(myAes.Key, false);
                            byte[] mes = Encoding.ASCII.GetBytes("{Key}");
                            
                            byte[] newArray = new byte[df.Length + mes.Length];
                            Array.Copy(mes, 0, newArray, 0, mes.Length);
                            Array.Copy(df, 0, newArray, mes.Length, df.Length);
                            handler.Send(newArray);
                        }
                    }
                    Thread.Sleep(1000);
                    // An incoming connection needs to be processed.
                    while (true)
                    {
                        bytes = new byte[1024];
                        int bytesRec = handler.Receive(bytes);

                        data = Encoding.UTF8.GetString(bytes, 0, bytesRec);
                        if (data.IndexOf("Ключ") > -1)
                        {
                            Console.Write("\nКлюч был успешно отправлен!\n");
                            byte[] encMes = EncryptFile(dlg.FileName, aesKey);
                            handler.Send(encMes);
                            Console.Write("\nФайл был успешно зашифрован и отправлен!\n");
                            handler.Shutdown(SocketShutdown.Both);
                            handler.Close();
                            break;
                        }
                    }
                    //Thread.Sleep(1000);
                   
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

        }
        Console.WriteLine("\nНажмите Enter для продолжения\n");
        Console.Read();

    }
    static byte[] EncryptFile(string sInputFilename, byte[] sKey)
    {
        FileStream fsInput = new FileStream(sInputFilename, FileMode.Open, FileAccess.Read);
        //fsEncrypted = new FileStream(sOutputFilename, FileMode.Create, FileAccess.Write);
        //AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
       // aes.KeySize = 256;
        //aes.Key = sKey;
        //aes.Padding = PaddingMode.Zeros;
        byte[] iv = new byte[16];
        //aes.IV = iv;
        string enc = Encoding.UTF8.GetString(File.ReadAllBytes(sInputFilename));
       // ICryptoTransform desencrypt = aes.CreateEncryptor(aes.Key, aes.IV);
        //CryptoStream cryptostream = new CryptoStream(, desencrypt, CryptoStreamMode.Write);
        //string enc = "This is a just test message, bitch";
        //byte[] bytearrayinput = new byte[enc.Length - 1];
        byte[] encrypted;// = new byte[fsInput.Length - 1];
       // fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
       // string tmp = Encoding.ASCII.GetString(bytearrayinput);
        //cryptostream.Write(bytearrayinput, 0, bytearrayinput.Length);

        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
        {
            aesAlg.KeySize = 256;
            aesAlg.BlockSize = 128;
            aesAlg.Mode = CipherMode.CBC;
           // aesAlg.Padding = PaddingMode.Zeros;
            aesAlg.Key = sKey;
            aesAlg.IV = iv;

            // Create a decrytor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption. 
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(enc);
                        swEncrypt.Flush();
                        swEncrypt.Close();
                    }
                    encrypted = msEncrypt.ToArray();
                    csEncrypt.Flush();
                    csEncrypt.Close();
                }
            }
            return encrypted;
        }
					
    }
    [STAThread]
    public static int Main(String[] args)
    {
        StartListening();
        return 0;
    }
}
