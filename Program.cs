// JANUS Demo — .NET Security Target  (ASP.NET Core Minimal API)
// DO NOT DEPLOY — intentionally vulnerable for demo purposes only.
//
// 4 seeded PCI-DSS vulnerabilities:
//
//  Finding 0  HIGH   pan-cvv-logging       POST /api/payments/charge
//  Finding 1  HIGH   webhook-amount-trust  POST /api/webhook/gateway
//  Finding 2  HIGH   broken-authz-idor     GET  /api/account/{id}
//  Finding 3  MEDIUM missing-idempotency   POST /api/payments/transfer
//
// Design notes:
//  - Charge handler uses db.ChargeHistory.Add() so missing-idempotency rule
//    does NOT fire there (rule only matches Transactions/Payments/Charges.Add).
//  - Transfer handler uses db.Transactions.Add() with no check → rule fires.
//  - Webhook variable named 'webhook' → webhook-amount-trust rule fires.
//  - db.Accounts is a List<Account> with FirstOrDefault() → broken-authz fires.
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new InMemoryLoggerProvider());

var store = new PaymentsStore();
store.Accounts.AddRange(new[] {
    new Account { Id = "alice", Password = "alice-pw", Balance = 1000m },
    new Account { Id = "bob",   Password = "bob-pw",   Balance = 500m  },
});
store.Orders["order-1001"] = new Order { Id = "order-1001", Amount = 75.00m,  Status = "pending" };
store.Orders["order-1002"] = new Order { Id = "order-1002", Amount = 120.50m, Status = "pending" };
builder.Services.AddSingleton(store);

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// AUTH
app.MapPost("/api/auth/login", async (HttpContext ctx, PaymentsStore db) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<LoginRequest>();
    var acc = db.Accounts.FirstOrDefault(a => a.Id == req?.Username && a.Password == req?.Password);
    if (acc is null) return Results.Unauthorized();
    var token = Guid.NewGuid().ToString("N");
    db.Tokens[token] = req!.Username!;
    return Results.Ok(new { token, username = req.Username });
});

// VULN 0: PAN/CVV LOGGING — POST /api/payments/charge
// Rule: payments.dotnet.pan-cvv-logging
// Charge records go to db.ChargeHistory (not db.Transactions) so the
// missing-idempotency rule does NOT fire here.
app.MapPost("/api/payments/charge", async (HttpContext ctx, ILogger<Program> logger, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();

    var chargeReq = await ctx.Request.ReadFromJsonAsync<ChargeRequest>();

    // VULNERABILITY: raw PAN and CVV written to logger — PCI DSS 3.2/3.3/3.4 violation
    logger.LogInformation("charge user={User} pan={Pan} cvv={Cvv} amount={Amount}",
        db.Tokens[auth], chargeReq!.Pan, chargeReq.Cvv, chargeReq.Amount);

    var txId = Guid.NewGuid().ToString("N")[..16];
    db.ChargeHistory.Add(new TxRecord { Id = txId, User = db.Tokens[auth],
        Amount = chargeReq.Amount, Pan = chargeReq.Pan, Cvv = chargeReq.Cvv });
    return Results.Ok(new { transaction_id = txId, amount = chargeReq.Amount, status = "approved" });
});

app.MapGet("/api/payments/logs", () => Results.Text(string.Join("\n", LogBuffer.Lines)));

// VULN 1: WEBHOOK AMOUNT TRUST — POST /api/webhook/gateway
// Rule: payments.dotnet.webhook-amount-trust
// Variable named 'webhook' matches the rule's source-variable regex.
app.MapPost("/api/webhook/gateway", async (HttpContext ctx, PaymentsStore db) =>
{
    var webhook = await ctx.Request.ReadFromJsonAsync<WebhookRequest>();
    if (!db.Orders.TryGetValue(webhook!.OrderId ?? "", out var order)) return Results.NotFound();

    // VULNERABILITY: trusts the amount from the forgeable gateway callback
    order.Amount = webhook.Amount;
    order.Status = "settled";
    return Results.Ok(new { order.Id, order.Amount, order.Status });
});

app.MapGet("/api/payments/order/{id}", (string id, PaymentsStore db) =>
    db.Orders.TryGetValue(id, out var o) ? Results.Ok(new { o.Id, o.Amount, o.Status }) : Results.NotFound());

// VULN 2: BROKEN AUTHORIZATION (IDOR) — GET /api/account/{id}
// Rule: payments.dotnet.broken-authz-idor
// db.Accounts.FirstOrDefault(...) matches the Semgrep pattern; no ownership check.
app.MapGet("/api/account/{id}", (string id, HttpContext ctx, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();

    // VULNERABILITY: authenticated but no ownership check — alice can read bob's balance
    var acc = db.Accounts.FirstOrDefault(x => x.Id == id);
    return acc is null ? Results.NotFound() : Results.Ok(new { acc.Id, acc.Balance });
});

// VULN 3: MISSING IDEMPOTENCY — POST /api/payments/transfer
// Rule: payments.dotnet.missing-idempotency
// db.Transactions.Add without any idempotency check → rule fires HERE ONLY.
app.MapPost("/api/payments/transfer", async (HttpContext ctx, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();

    var req = await ctx.Request.ReadFromJsonAsync<TransferRequest>();
    // VULNERABILITY: no Idempotency-Key check — network retry creates duplicate transfer
    var txId = Guid.NewGuid().ToString("N")[..16];
    db.Transactions.Add(new TxRecord { Id = txId, User = db.Tokens[auth], Amount = req!.Amount });
    return Results.Ok(new { transaction_id = txId, amount = req.Amount, status = "transferred" });
});

app.MapGet("/api/payments/transactions", (PaymentsStore db) =>
    Results.Ok(db.ChargeHistory.Concat(db.Transactions)
        .Select(t => new { t.Id, t.User, t.Amount })));

app.Run();

static string? GetToken(HttpContext ctx)
{
    var h = ctx.Request.Headers["Authorization"].ToString();
    return h.StartsWith("Bearer ") ? h[7..] : null;
}

public record LoginRequest(string? Username, string? Password);
public record ChargeRequest(decimal Amount, string? Pan, string? Cvv);
public record WebhookRequest(string? OrderId, decimal Amount, string? Signature);
public record TransferRequest(string? FromAccount, string? ToAccount, decimal Amount);

public class Account  { public string Id { get; set; } = ""; public string Password { get; set; } = ""; public decimal Balance { get; set; } }
public class Order    { public string Id { get; set; } = ""; public decimal Amount { get; set; } public string Status { get; set; } = ""; }
public class TxRecord { public string Id { get; set; } = ""; public string User { get; set; } = ""; public decimal Amount { get; set; } public string? Pan { get; set; } public string? Cvv { get; set; } }

public class PaymentsStore
{
    public List<Account>              Accounts      { get; } = new();
    public Dictionary<string, Order>  Orders        { get; } = new();
    public List<TxRecord>             Transactions  { get; } = new();  // transfers (idempotency rule fires)
    public List<TxRecord>             ChargeHistory { get; } = new();  // charges (idempotency rule suppressed)
    public Dictionary<string, string> Tokens        { get; } = new();
}

public static class LogBuffer { public static readonly ConcurrentQueue<string> Lines = new(); }
public class InMemoryLoggerProvider : ILoggerProvider { public ILogger CreateLogger(string c) => new InMemoryLogger(); public void Dispose() { } }
public class InMemoryLogger : ILogger
{
    public IDisposable BeginScope<T>(T s) => null!;
    public bool IsEnabled(LogLevel l) => true;
    public void Log<T>(LogLevel l, EventId e, T s, Exception? ex, Func<T, Exception?, string> f)
    { if (f != null) LogBuffer.Lines.Enqueue(f(s, ex)); }
}
