#region Library References
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using UAParser;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
#endregion

namespace Project.GlobalClasses
{
    public class MethodFactory
    {
        #region Declarations
        byte[] iv = new byte[16];
        string aesKey = "yourComplicatedKey";
        private IHttpContextAccessor _httpContextAccessor;

        public IConfiguration Configuration { get; }

        public MethodFactory(IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
            this._httpContextAccessor = httpContextAccessor;
            Configuration = configuration;
        }
        #endregion

        #region GetClientInfo
        private ClientInfo GetClientInfo()
        {
            var userAgent = _httpContextAccessor.HttpContext.Request.Headers["User-Agent"];
            string uaString = Convert.ToString(userAgent[0]);
            var uaParser = Parser.GetDefault();
            ClientInfo clientInfo = uaParser.Parse(uaString);

            return clientInfo;
        }
        #endregion

        #region GetBrowser
        public string GetBrowser()
        {
            ClientInfo clientInfo = GetClientInfo();

            var browser = clientInfo.UA;
            return string.Format("{0}", browser);
        }
        #endregion

        #region GetOS
        public string GetOS()
        {
            ClientInfo clientInfo = GetClientInfo();
            return clientInfo.OS.ToString();
        }
        #endregion

        #region GetIP
        public string GetIP()
        {
            string ipAdd = _httpContextAccessor.HttpContext.Connection.RemoteIpAddress?.ToString();

            return ipAdd.Replace("::1", SD.LocalIP);
        }
        #endregion
        

        #region GetHash
        public string GetHash(string text)
        {
            // SHA512 is disposable by inheritance.  
            using (var sha512 = SHA512.Create())
            {
                // Send a sample text to hash.  
                var hashedBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(text));
                // Get the hashed string.  
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
        #endregion

        #region GetSalt
        public string GetSalt()
        {
            byte[] bytes = new byte[128 / 8];
            using (var keyGenerator = RandomNumberGenerator.Create())
            {
                keyGenerator.GetBytes(bytes);
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }
        #endregion

        #region EncryptString
        public string EncryptString(string text)
        {
            try
            {
                using (Aes myAes = Aes.Create())
                {
                    myAes.IV = iv;
                    myAes.Key = Encoding.UTF8.GetBytes(aesKey);

                    // Encrypt the string to an array of bytes.
                    byte[] encryptedString = EncryptStringToBytes_Aes(text, myAes.Key, myAes.IV);

                    return Convert.ToBase64String(encryptedString);
                }
            }
            catch (Exception)
            {
                return null;
            }

        }
        
        #region EncryptionImplementation
        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        #endregion
        
        #endregion

        #region DecryptString
        public string DecryptString(string encryptedString)
        {
            try
            {
                byte[] buffer = Convert.FromBase64String(encryptedString);
                using (Aes myAes = Aes.Create())
                {
                    myAes.IV = iv;
                    myAes.Key = Encoding.UTF8.GetBytes(aesKey);

                    // Decrypt the bytes to a string.
                    string decryptedString = DecryptStringFromBytes_Aes(buffer, myAes.Key, myAes.IV);

                    return decryptedString;
                }
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        #region DecryptionImplementation
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        #endregion

        #endregion

        #region GetInfoByIP
        public string GetUserCountryByIp(string ip)
        {
            IpInfo ipInfo = new IpInfo();
            try
            {
                string info = new WebClient().DownloadString("http://ipinfo.io/" + ip);
                ipInfo = JsonConvert.DeserializeObject<IpInfo>(info);
                RegionInfo myRI1 = new RegionInfo(ipInfo.Country);
                ipInfo.Country = myRI1.EnglishName;
            }
            catch (Exception)
            {
                ipInfo.Country = null;
            }

            return ipInfo.Country;
        }
        #endregion

        #region GetUserDevice
        public UserDevice GetUserDevice()
        {
            string manufacturer = null, model = null, deviceName = Environment.MachineName;
            try
            {
                SelectQuery query = new SelectQuery(@"Select * from Win32_ComputerSystem");

                //initialize the searcher with the query it is supposed to execute
                using (ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(query))
                {
                    //execute the query
                    foreach (System.Management.ManagementObject process in searcher.Get())
                    {
                        //print system info
                        process.Get();
                        manufacturer = process["Manufacturer"].ToString();
                        model = process["Model"].ToString();
                    }
                }
                return new UserDevice
                {
                    Manufacturer = manufacturer,
                    Model = model,
                    DeviceName = deviceName
                };
            }
            catch (Exception)
            {
                return null;
            }
        }
        #endregion

        #region GetActiveMACAddress
        public List<string> GetActiveMacAddress(string separator = "-")
        {
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();

            if (nics == null || nics.Length < 1)
            {
                //Debug.WriteLine(" No network interfaces found.");
                return null;
            }

            var macAddress = new List<string>();

            //Debug.WriteLine(" Number of interfaces .................... : {0}", nics.Length);
            foreach (NetworkInterface adapter in nics.Where(c =>
             c.NetworkInterfaceType != NetworkInterfaceType.Loopback && c.OperationalStatus == OperationalStatus.Up))
            {
                IPInterfaceProperties properties = adapter.GetIPProperties();

                var unicastAddresses = properties.UnicastAddresses;
                if (unicastAddresses.Any(temp => temp.Address.AddressFamily == AddressFamily.InterNetwork))
                {
                    var address = adapter.GetPhysicalAddress();
                    if (string.IsNullOrEmpty(separator))
                    {
                        macAddress.Add(address.ToString());
                    }
                    else
                    {
                        string mac = (Regex.Replace(address.ToString(), ".{2}", "$0:"));
                        macAddress.Add(mac.TrimEnd(':'));
                        //macAddress.Add(string.Join(separator, address.GetAddressBytes()));
                    }
                }
            }

            return macAddress;
        }
        #endregion

        #region GetYear
        public string GetYear()
        {
            return DateTime.Now.Year.ToString();
        }
        #endregion

        #region GetDate
        public DateTime GetDate()
        {
            return DateTime.UtcNow;
        }
        #endregion

        #region GetBasicProperties
        public BaseProperties GetBaseProperties()
        {
            UserDevice userDevice = GetUserDevice();

            BaseProperties baseProperties = new BaseProperties
            {
                CreatedDate = GetDate(),
                IP = GetIP(),
                Browser = GetBrowser(),
                OS = GetOS(),
                Manufacturer = userDevice.Manufacturer,
                DeviceName = userDevice.DeviceName,
                ModelName = userDevice.Model,
                MacAddress = GetActiveMacAddress()[0],
            };

            return baseProperties;
        }
        #endregion

        #region GetApUrl
        public string GetAppUrl()
        {
            return Configuration["AppSettings:App_URL"].ToString() == null ? string.Empty : Configuration["AppSettings:App_URL"].ToString();
        }
        #endregion

    }
}
