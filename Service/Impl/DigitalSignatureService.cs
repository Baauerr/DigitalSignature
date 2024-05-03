using System.Security.Cryptography;
using System.Xml.Serialization;
using DigitalSignature.DocumentData;


namespace DigitalSignature.Service.Impl
{

    public class DigitalSignatureService : IDigitalSignature
    {

        //Проверяет подпись
        public bool CheckSignature(string fileName)
        {
            var publicKeyPath = $"C:\\Users\\Артем\\Desktop\\GAGA\\DigitalSignature\\files\\{fileName}-publicKey.txt";
            var documentPath = $"C:\\Users\\Артем\\Desktop\\GAGA\\DigitalSignature\\files\\{fileName}";

            RSAParameters publicKey = GetPublicKeyFromFile(publicKeyPath);

            DocumentWithMetadata allDocument = GetHashFromFileMetadata(documentPath);

            byte[] documentHash = HashDocument(allDocument.EncryptedData);

            using (RSA rsa = RSA.Create(publicKey))
            {
                return rsa.VerifyData(documentHash, allDocument.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        //Достаёт публичный ключ из файла 

        private RSAParameters GetPublicKeyFromFile(string publicKeyPath)
        {
            RSAParameters publicKey;
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));
            using (FileStream fs = new FileStream(publicKeyPath, FileMode.Open))
            {
                publicKey = (RSAParameters)serializer.Deserialize(fs);
            }
            return publicKey;
        }

        //Главная функция, которая отвечает за цифровую подпись

        public string CreateSignature(string fileName)
        {
            var documentPath = $"C:\\Users\\Артем\\Desktop\\GAGA\\DigitalSignature\\files\\{fileName}";
            var documentBytes = GetFile(documentPath);
            var hashDocument = HashDocument(documentBytes);
            var encryptedHash = AssymetricEncryptHash(hashDocument, fileName);
            AddHashToFile(documentPath, encryptedHash.HashedData);
            return encryptedHash.publicKey;
        }

        //Разделяем документ с подписью на исходные данные + подпись 

        private DocumentWithMetadata GetHashFromFileMetadata(string filePath)
        {
            byte[] fileContent = File.ReadAllBytes(filePath);

            int dataSize = fileContent.Length - 256; 
            byte[] data = new byte[dataSize];
            byte[] signature = new byte[256];
            Array.Copy(fileContent, 0, data, 0, dataSize);
            Array.Copy(fileContent, dataSize, signature, 0, 256);

            var newDoc = new DocumentWithMetadata
            {
                EncryptedData = data,
                Signature = signature
            };

            return newDoc;

        }
        
        //Добавляем подпись в конец битовой записи файла (типа зашиваем в метаданные)
        
        private void AddHashToFile(string filePath, byte[] hash)
        {
            using (FileStream targetFileStream = new FileStream(filePath, FileMode.Append))
            {
                targetFileStream.Write(hash, 0, hash.Length);
            }
        }

        //Получение файла 

        private byte[] GetFile(string filePath)
        {
            byte[] documentBytes = File.ReadAllBytes(filePath);
            return documentBytes;
        }

        //Хеширование документа при помощи SHA256

        private byte[] HashDocument(byte[] documentBytes)
        {
            byte[] hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(documentBytes);
            }
            return hash;
        }


        //Ассиметричное шифрование захешированного документа

        private SignWithKey AssymetricEncryptHash(byte[] documentHash, string fileName)
        {
            RSA rsa = RSA.Create();

            byte[] encryptedBytes = Encrypt(rsa.ExportParameters(true), documentHash);

            RSAParameters publicKey = rsa.ExportParameters(false);

            string publicKeyPath = $"C:\\Users\\Артем\\Desktop\\GAGA\\DigitalSignature\\files\\{fileName}-publicKey.txt";

            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));
            using (TextWriter writer = new StreamWriter(publicKeyPath))
            {
                serializer.Serialize(writer, publicKey);
            }

            var xmlKey = RSAParametersToXml(publicKey);

            var signWithKey = new SignWithKey
            {
                HashedData = encryptedBytes,
                publicKey = xmlKey
            };

            return signWithKey;

        }

        //Преобразование публичного ключа в XML, чтобы удобно было его хранить 

        static string RSAParametersToXml(RSAParameters parameters)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));
            using (StringWriter writer = new StringWriter())
            {
                serializer.Serialize(writer, parameters);
                return writer.ToString();
            }
        }

        //Шифровка ключа при помощи RSA приватным ключом + возврат подписи 

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

