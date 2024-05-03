namespace DigitalSignature.DocumentData
{
    public class SignedDocumentWithKey
    {
        public byte[] FileWithSignature { get; set; }
        public string publicKey { get; set; }
    }
}
