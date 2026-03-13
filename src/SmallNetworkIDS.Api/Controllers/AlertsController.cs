using Microsoft.AspNetCore.Mvc;
using SmallNetworkIDS.Api.Services;
using SmallNetworkIDS.Core.Models;

namespace SmallNetworkIDS.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AlertsController : ControllerBase
{
    private readonly IDSService _idsService;

    public AlertsController(IDSService idsService)
    {
        _idsService = idsService;
    }

    /// <summary>
    /// Get recent alerts
    /// </summary>
    [HttpGet("recent")]
    public ActionResult<List<AlertEvent>> GetRecentAlerts([FromQuery] int limit = 100)
    {
        return Ok(_idsService.GetRecentAlerts(limit));
    }

    /// <summary>
    /// Get alert statistics
    /// </summary>
    [HttpGet("stats")]
    public ActionResult<AlertStats> GetStats()
    {
        return Ok(_idsService.GetAlertStats());
    }

    /// <summary>
    /// Get alerts by type
    /// </summary>
    [HttpGet("by-type/{type}")]
    public ActionResult<List<AlertEvent>> GetAlertsByType(AlertType type, [FromQuery] int limit = 50)
    {
        var alerts = _idsService.GetRecentAlerts(limit * 2)
            .Where(a => a.Type == type)
            .Take(limit)
            .ToList();
        return Ok(alerts);
    }
}
