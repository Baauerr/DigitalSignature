using System.Security.Cryptography;
using System.Xml;
using System.Xml.Serialization;
using DigitalSignature.DocumentData;


namespace DigitalSignature.Service.Impl
{

    public class DigitalSignatureService : IDigitalSignature
    {
        public bool CheckSignature(IFormFile file, string publicKeyXML)
        {

            var fileBytes = ConvertIFormFileToByteArray(file);

            RSAParameters publicKeyRSA = ConvertXmlPublicKeyToRsaParameters(publicKeyXML);

            DocumentWithMetadata allDocument = GetHashFromFileMetadata(fileBytes);

            byte[] documentHash = HashDocument(allDocument.EncryptedData);

            using (RSA rsa = RSA.Create(publicKeyRSA))
            {
                return rsa.VerifyData(documentHash, allDocument.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static RSAParameters ConvertXmlPublicKeyToRsaParameters(string xmlPublicKey)
        {
            RSAParameters rsaParams = new RSAParameters();

            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(xmlPublicKey);


                byte[] modulusBytes = Convert.FromBase64String(xmlDoc.SelectSingleNode("//Modulus").InnerText);
                byte[] exponentBytes = Convert.FromBase64String(xmlDoc.SelectSingleNode("//Exponent").InnerText);

                rsaParams.Modulus = modulusBytes;
                rsaParams.Exponent = exponentBytes;

                return rsaParams;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error converting XML public key to RSAParameters: " + ex.Message);
                throw;
            }
        }

        public byte[] ConvertIFormFileToByteArray(IFormFile file)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                file.CopyTo(ms);
                return ms.ToArray();
            }
        }

        public string CreateSignature(IFormFile file)
        {

            var pathToSaveFile = Environment.CurrentDirectory + $"\\files\\{file.FileName}";


            var documentBytes = ConvertIFormFileToByteArray(file);
            var hashDocument = HashDocument(documentBytes);
            var encryptedHash = AssymetricEncryptHash(hashDocument);
            AddHashToFile(pathToSaveFile, encryptedHash.FileWithSignature);

            return encryptedHash.publicKey;
        }

        private DocumentWithMetadata GetHashFromFileMetadata(byte[] file) 
        {

            if (file.Length < 256)
            {
                throw new ArgumentException("File haven't signature, bro");
            }


            int dataSize = file.Length - 256; 
            byte[] data = new byte[dataSize];
            byte[] signature = new byte[256];
            Array.Copy(file, 0, data, 0, dataSize);
            Array.Copy(file, dataSize, signature, 0, 256);

            var newDoc = new DocumentWithMetadata
            {
                EncryptedData = data,
                Signature = signature
            };

            return newDoc;

        }

        private void AddHashToFile(string filePath, byte[] hash)
        {
            using (FileStream targetFileStream = new FileStream(filePath, FileMode.Append))
            {
                targetFileStream.Write(hash, 0, hash.Length);
            }
        }

        private byte[] HashDocument(byte[] documentBytes)
        {
            byte[] hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(documentBytes);
            }
            return hash;
        }

        private SignedDocumentWithKey AssymetricEncryptHash(byte[] documentHash)
        {
            RSA rsa = RSA.Create();

            byte[] encryptedBytes = Encrypt(rsa.ExportParameters(true), documentHash);

            RSAParameters publicKey = rsa.ExportParameters(false);

            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));

            var xmlKey = RSAParametersToXml(publicKey);

            var signWithKey = new SignedDocumentWithKey
            {
                FileWithSignature = encryptedBytes,
                publicKey = xmlKey
            };

            return signWithKey;

        }

        static string RSAParametersToXml(RSAParameters parameters)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));
            using (StringWriter writer = new StringWriter())
            {
                serializer.Serialize(writer, parameters);
                return writer.ToString();
            }
        }

        private byte[] Encrypt(RSAParameters privateKey, byte[] documentHash)
        {
            using (RSA rsa = RSA.Create(privateKey))
            {
                byte[] signature = rsa.SignData(documentHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return signature;
            }
        }
    }
}

