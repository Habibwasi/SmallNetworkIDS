using Microsoft.AspNetCore.Mvc;
using SmallNetworkIDS.Api.Services;

namespace SmallNetworkIDS.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ThreatsController : ControllerBase
{
    private readonly IDSService _idsService;

    public ThreatsController(IDSService idsService)
    {
        _idsService = idsService;
    }

    /// <summary>
    /// Get top threat IPs
    /// </summary>
    [HttpGet("top")]
    public ActionResult<List<ThreatIP>> GetTopThreats([FromQuery] int limit = 10)
    {
        return Ok(_idsService.GetTopThreats(limit));
    }
}
