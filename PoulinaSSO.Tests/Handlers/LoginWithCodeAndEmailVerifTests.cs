using FluentAssertions;
using Moq;
using System.Security.Cryptography;
using Domain.Commands.Auth;
using Domain.Handlers.Auth;
using Domain.Interfaces;
using PoulinaSSO.Tests.Helpers;
using Xunit;

namespace PoulinaSSO.Tests.Handlers;

/// <summary>
/// Tests unitaires pour RegisterHandler et la vérification d'email.
/// Couvre : email de confirmation envoyé à la création, email déjà existant,
/// mot de passe trop court.
/// </summary>
public class EmailVerificationHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly Mock<IEmailService>   _emailMock;

    public EmailVerificationHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _emailMock  = new Mock<IEmailService>();

        _emailMock.Setup(e => e.EnvoyerEmailConfirmationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _emailMock.Setup(e => e.RenvoyerEmailConfirmationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
    }

    // ── RegisterHandler : email de confirmation envoyé à la création ──────────

    [Fact]
    public async Task Register_NouvelUtilisateur_EnvoieEmailDeConfirmation()
    {
        var handler = new RegisterHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object, _emailMock.Object);

        _repoMock.Setup(r => r.EmailExisteAsync(It.IsAny<string>(), default)).ReturnsAsync(false);
        _hasherMock.Setup(h => h.Hash(It.IsAny<string>())).Returns("hashed_pw");

        var cmd = new RegisterCommand(new RegisterRequest
        {
            Email    = "new@poulina.com",
            Password = "Password123!",
            Nom      = "Dupont",
            Prenom   = "Jean"
        });

        var result = await handler.Handle(cmd, default);

        result.Success.Should().BeTrue();
        _emailMock.Verify(e => e.EnvoyerEmailConfirmationAsync(
            "new@poulina.com",
            It.IsAny<string>(),
            It.Is<string>(l => l.Contains("/api/Auth/confirm-email?token=")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Register_EmailDejaExistant_RetourneEchec()
    {
        var handler = new RegisterHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object, _emailMock.Object);

        _repoMock.Setup(r => r.EmailExisteAsync(It.IsAny<string>(), default)).ReturnsAsync(true);

        var cmd = new RegisterCommand(new RegisterRequest
        {
            Email    = "existing@poulina.com",
            Password = "Password123!",
            Nom      = "Dupont",
            Prenom   = "Jean"
        });

        var result = await handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("existe déjà");
        _emailMock.Verify(e => e.EnvoyerEmailConfirmationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Register_MotDePasseTropCourt_RetourneEchec()
    {
        var handler = new RegisterHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object, _emailMock.Object);

        var cmd = new RegisterCommand(new RegisterRequest
        {
            Email    = "user@poulina.com",
            Password = "abc",   // < 8 caractères
            Nom      = "Dupont",
            Prenom   = "Jean"
        });

        var result = await handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("8 caractères");
    }
}