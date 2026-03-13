using Microsoft.AspNetCore.Mvc;
using SmallNetworkIDS.Api.Services;
using SmallNetworkIDS.Core.Models;

namespace SmallNetworkIDS.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class FlowsController : ControllerBase
{
    private readonly IDSService _idsService;

    public FlowsController(IDSService idsService)
    {
        _idsService = idsService;
    }

    /// <summary>
    /// Get recent network flows
    /// </summary>
    [HttpGet("recent")]
    public ActionResult<List<NetworkFlow>> GetRecentFlows([FromQuery] int limit = 500)
    {
        return Ok(_idsService.GetRecentFlows(limit));
    }

    /// <summary>
    /// Get network statistics
    /// </summary>
    [HttpGet("stats")]
    public ActionResult<NetworkStats> GetStats()
    {
        return Ok(_idsService.GetNetworkStats());
    }
}
