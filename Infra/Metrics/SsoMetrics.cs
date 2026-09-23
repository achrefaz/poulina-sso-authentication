﻿using System.Diagnostics.Metrics;
using Domain.Interfaces;  

namespace Infra.Metrics;

public class SsoMetrics : ISsoMetrics   
{
    public const string MeterName = "PoulinaSSO.Business";

    private readonly Counter<long> _loginsSuccess;
    private readonly Counter<long> _loginsFailed;
    private readonly Counter<long> _loginsRateLimited;
    private readonly Counter<long> _tokensIssued;
    private readonly Counter<long> _accountsLocked;

    public SsoMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName);

        _loginsSuccess = meter.CreateCounter<long>(
            name: "sso_logins_total_success",
            unit: "{login}",
            description: "Nombre de connexions réussies");

        _loginsFailed = meter.CreateCounter<long>(
            name: "sso_logins_total_failed",
            unit: "{login}",
            description: "Nombre de connexions échouées");

        _loginsRateLimited = meter.CreateCounter<long>(
            name: "sso_logins_total_rate_limited",
            unit: "{login}",
            description: "Nombre de connexions bloquées par rate limiter");

        _tokensIssued = meter.CreateCounter<long>(
            name: "sso_tokens_issued_total",
            unit: "{token}",
            description: "Nombre de tokens JWT émis");

        _accountsLocked = meter.CreateCounter<long>(
            name: "sso_accounts_locked_total",
            unit: "{account}",
            description: "Nombre de comptes verrouillés");
    }
    
    public void RecordLoginSuccess(string method = "password")
        => _loginsSuccess.Add(1, new KeyValuePair<string, object?>("method", method));

    public void RecordLoginFailed(string reason = "invalid_credentials")
        => _loginsFailed.Add(1, new KeyValuePair<string, object?>("reason", reason));

    public void RecordLoginRateLimited()
        => _loginsRateLimited.Add(1);

    public void RecordTokenIssued(string type = "access")
        => _tokensIssued.Add(1, new KeyValuePair<string, object?>("type", type));

    public void RecordAccountLocked()
        => _accountsLocked.Add(1);
}