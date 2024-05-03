namespace DigitalSignature.DocumentData
{
    public class SignWithKey
    {
        public byte[] HashedData { get; set; }
        public string publicKey { get; set; }
    }
    public class VerifyDocumentDTO
    {
        public string documentName { get; set; }
    }
}
