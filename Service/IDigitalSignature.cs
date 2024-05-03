using DigitalSignature.DocumentData;

namespace DigitalSignature.Service
{
    public interface IDigitalSignature
    {
        public string CreateSignature(IFormFile file);
        public bool CheckSignature(IFormFile file, string publicKey);
    }
}
