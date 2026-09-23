namespace Domain.Interfaces;

public interface ISsoMetrics
{
    void RecordLoginSuccess(string method = "password");
    void RecordLoginFailed(string reason = "invalid_credentials");
    void RecordLoginRateLimited();
    void RecordTokenIssued(string type = "access");
    void RecordAccountLocked();
}