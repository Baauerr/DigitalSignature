using Aspose.Pdf.Plugins;
using DigitalSignature.DocumentData;
using DigitalSignature.Service;
using DigitalSignature.Service.Impl;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSignature.Controllers
{
    [Route("api/digitalSignature")]
    public class DigitalSignatureController : Controller
    {
        private readonly IDigitalSignature _digitalSignature;

        public DigitalSignatureController(IDigitalSignature digitalSignature)
        {
            _digitalSignature = digitalSignature;
        }

        [HttpPost("create")]
        public IActionResult SignDocument(IFormFile file)
        {

            var publicKey = _digitalSignature.CreateSignature(file);

            return Ok(publicKey);
        }

        [HttpPost("check")]
        public IActionResult CheckSignature(string publicKey, IFormFile file)
        {
            var signatureIsValid = _digitalSignature.CheckSignature(file, publicKey);
            return Ok(signatureIsValid);
        }
    }
}
