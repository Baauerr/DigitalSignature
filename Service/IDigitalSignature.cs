using DigitalSignature.DocumentData;

namespace DigitalSignature.Service
{
    public interface IDigitalSignature
    {
        public string CreateSignature(string fileName);
        public bool CheckSignature(string fileName);
        

    }
}
