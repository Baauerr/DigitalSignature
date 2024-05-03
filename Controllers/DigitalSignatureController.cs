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

            return Ok(_digitalSignature.CreateSignature(file));
        }

        [HttpPost("check")]
        public IActionResult CheckSignature([FromBody] VerifyDocumentDTO verifyData)
        {
            var signatureIsValid = _digitalSignature.CheckSignature(verifyData.documentName);
            return Ok(signatureIsValid);
        }
    }
}
