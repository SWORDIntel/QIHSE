using Microsoft.AspNetCore.Mvc;
using Qihse.Studio.Server.Models;
using Qihse.Studio.Server.Services;

namespace Qihse.Studio.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TelemetryController : ControllerBase
{
    private readonly ClusterMeshService _meshService;

    public TelemetryController(ClusterMeshService meshService)
    {
        _meshService = meshService;
    }

    [HttpGet("snapshot")]
    public ActionResult<TelemetryFrame> GetSnapshot()
    {
        return Ok(_meshService.LatestFrame);
    }

    [HttpGet("nodes")]
    public ActionResult<List<QihseNode>> GetNodes()
    {
        return Ok(_meshService.LatestFrame.Nodes);
    }
}
