using MediatR;

namespace Domain.Commands.Auth
{
   
    public record ConfirmEmailCommand(string Token) : IRequest<ConfirmEmailResult>;

    public class ConfirmEmailResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }
    
    public record RenvoyerConfirmationEmailCommand(string Email) : IRequest<RenvoyerConfirmationEmailResult>;

    public class RenvoyerConfirmationEmailResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }
}