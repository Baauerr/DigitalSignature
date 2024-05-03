namespace DigitalSignature.DocumentData
{
    public class DocumentWithMetadata
    {
        public byte[] EncryptedData { get; set; }
        public byte[] Signature { get; set; }
    }
}
