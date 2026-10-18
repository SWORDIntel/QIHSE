using Microsoft.AspNetCore.Mvc;
using Qihse.Studio.Server.Models;

namespace Qihse.Studio.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VectorController : ControllerBase
{
    [HttpPost("search")]
    public IActionResult Search([FromBody] VectorSearchRequest request) =>
        StatusCode(StatusCodes.Status501NotImplemented,
            new { error = "Authorization-aware native vector search is not yet connected." });
}
