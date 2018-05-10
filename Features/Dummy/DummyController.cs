using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace StarterWebJwt.Features.Dummy
{
    public class DummyController : ApiController
    {
        public IActionResult Get()
        {
            return Ok();
        }

        [Authorize("SomePolicy")]
        [Route("some-claim")]
        public IActionResult GetWithClaim()
        {
            return Ok();
        }
    }
}