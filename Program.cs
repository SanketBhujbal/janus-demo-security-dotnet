// JANUS Demo — .NET Security Target  (ASP.NET Core Minimal API)
// DO NOT DEPLOY — intentionally vulnerable for demo purposes only.
//
// 4 seeded PCI-DSS vulnerabilities mapping 1-to-1 to Semgrep rules in
// orchestrator/rules/payments_dotnet/:
//
//  Finding 0  HIGH   pan-cvv-logging           POST /api/payments/charge
//  Finding 1  HIGH   webhook-amount-trust       POST /api/webhook/gateway
//  Finding 2  HIGH   broken-authz               GET  /api/account/{id}
//  Finding 3  MEDIUM missing-idempotency        POST /api/payments/transfer
//
// Demo flow  (JANUS Security Brain):
//   Findings 0-2  → exploit ✅  patch ✅  validate ✅  (VALIDATED)
//   Finding  3    → exploit ✅  patch ✅  validate ❌  (FAILED — tests break after
//                   the healer adds the Idempotency-Key guard because the test
//                   suite sends a request without that header and now gets 400)
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new InMemoryLoggerProvider());

var store = new PaymentsStore();
store.Accounts["alice"] = new Account { Id = "alice", Password = "alice-pw", Balance = 1000m };
store.Accounts["bob"]   = new Account { Id = "bob",   Password = "bob-pw",   Balance = 500m  };
store.Orders["order-1001"] = new Order { Id = "order-1001", Amount = 75.00m, Status = "pending" };
store.Orders["order-1002"] = new Order { Id = "order-1002", Amount = 120.50m, Status = "pending" };
builder.Services.AddSingleton(store);

var app = builder.Build();

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.MapPost("/api/auth/login", async (HttpContext ctx, PaymentsStore db) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<LoginRequest>();
    if (req is null || !db.Accounts.TryGetValue(req.Username ?? "", out var acc))
        return Results.Unauthorized();
    if (acc.Password != req.Password) return Results.Unauthorized();
    var token = Guid.NewGuid().ToString("N");
    db.Tokens[token] = req.Username!;
    return Results.Ok(new { token, username = req.Username });
});

// ── VULN 1: PAN/CVV LOGGING — POST /api/payments/charge ──────────────────────
// Rule: payments.dotnet.pan-cvv-logging
// Exploit: POST with PAN + CVV, then GET /api/payments/logs — both visible plaintext
app.MapPost("/api/payments/charge", async (HttpContext ctx, ILogger<Program> logger, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();

    var req = await ctx.Request.ReadFromJsonAsync<ChargeRequest>();

    // VULNERABILITY: raw PAN and CVV written to logger — PCI DSS 3.2/3.3/3.4 violation
    logger.LogInformation("charge user={User} pan={Pan} cvv={Cvv} amount={Amount}",
        db.Tokens[auth], req!.Pan, req.Cvv, req.Amount);

    var txId = Guid.NewGuid().ToString("N")[..16];
    db.Transactions.Add(new TxRecord { Id = txId, User = db.Tokens[auth],
        Amount = req.Amount, Pan = req.Pan, Cvv = req.Cvv });
    return Results.Ok(new { transaction_id = txId, amount = req.Amount, status = "approved" });
});

app.MapGet("/api/payments/logs", () => Results.Text(string.Join("\n", LogBuffer.Lines)));

// ── VULN 2: WEBHOOK AMOUNT TRUST — POST /api/webhook/gateway ─────────────────
// Rule: payments.dotnet.webhook-amount-trust
// Exploit: POST webhook for order-1001 with amount=-9999 → order settled at negative amount
app.MapPost("/api/webhook/gateway", async (HttpContext ctx, PaymentsStore db) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<WebhookRequest>();
    if (!db.Orders.TryGetValue(req!.OrderId ?? "", out var order)) return Results.NotFound();

    // VULNERABILITY: trusts the amount in the (forgeable) gateway callback
    // instead of reconciling against the authoritative order record
    order.Amount = req.Amount;
    order.Status = "settled";
    return Results.Ok(new { order.Id, order.Amount, order.Status });
});

app.MapGet("/api/payments/order/{id}", (string id, PaymentsStore db) =>
    db.Orders.TryGetValue(id, out var o) ? Results.Ok(new { o.Id, o.Amount, o.Status }) : Results.NotFound());

// ── VULN 3: BROKEN AUTHORIZATION — GET /api/account/{id} ─────────────────────
// Rule: payments.dotnet.broken-authz
// Exploit: authenticate as alice, fetch /api/account/bob — no ownership check
app.MapGet("/api/account/{id}", (string id, HttpContext ctx, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();
    // VULNERABILITY: confirms caller is logged in but does NOT verify they own account {id}
    if (!db.Accounts.TryGetValue(id, out var acc)) return Results.NotFound();
    return Results.Ok(new { acc.Id, acc.Balance });
});

// ── VULN 4: MISSING IDEMPOTENCY — POST /api/payments/transfer ────────────────
// Rule: payments.dotnet.missing-idempotency
// Exploit: POST twice with same body → two transfers created (replay attack)
// DEMO: After the healer adds the Idempotency-Key guard, the test that calls
//       this endpoint without the header gets 400 → tests fail → FAILED status.
app.MapPost("/api/payments/transfer", async (HttpContext ctx, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();

    var req = await ctx.Request.ReadFromJsonAsync<TransferRequest>();
    // VULNERABILITY: no Idempotency-Key check — replay creates a second transfer
    var txId = Guid.NewGuid().ToString("N")[..16];
    db.Transactions.Add(new TxRecord { Id = txId, User = db.Tokens[auth],
        Amount = req!.Amount });
    return Results.Ok(new { transaction_id = txId, amount = req.Amount, status = "transferred" });
});

app.MapGet("/api/payments/transactions", (PaymentsStore db) =>
    Results.Ok(db.Transactions.Select(t => new { t.Id, t.User, t.Amount })));

app.Run();

// ── helpers ──────────────────────────────────────────────────────────────────
static string? GetToken(HttpContext ctx)
{
    var h = ctx.Request.Headers["Authorization"].ToString();
    return h.StartsWith("Bearer ") ? h[7..] : null;
}

// ── DTOs ─────────────────────────────────────────────────────────────────────
public record LoginRequest(string? Username, string? Password);
public record ChargeRequest(decimal Amount, string? Pan, string? Cvv);
public record WebhookRequest(string? OrderId, decimal Amount, string? Signature);
public record TransferRequest(string? FromAccount, string? ToAccount, decimal Amount);

// ── domain ────────────────────────────────────────────────────────────────────
public class Account  { public string Id { get; set; } = ""; public string Password { get; set; } = ""; public decimal Balance { get; set; } }
public class Order    { public string Id { get; set; } = ""; public decimal Amount { get; set; } public string Status { get; set; } = ""; }
public class TxRecord { public string Id { get; set; } = ""; public string User { get; set; } = ""; public decimal Amount { get; set; } public string? Pan { get; set; } public string? Cvv { get; set; } }

public class PaymentsStore
{
    public Dictionary<string, Account>  Accounts     { get; } = new();
    public Dictionary<string, Order>    Orders       { get; } = new();
    public List<TxRecord>               Transactions { get; } = new();
    public Dictionary<string, string>   Tokens       { get; } = new();  // token -> username
    public Dictionary<string, string>   Idempotency  { get; } = new();  // key -> txId (available but unused)
}

// ── in-memory log sink ────────────────────────────────────────────────────────
public static class LogBuffer { public static readonly ConcurrentQueue<string> Lines = new(); }
public class InMemoryLoggerProvider : ILoggerProvider { public ILogger CreateLogger(string c) => new InMemoryLogger(); public void Dispose() { } }
public class InMemoryLogger : ILogger
{
    public IDisposable BeginScope<T>(T s) => null!;
    public bool IsEnabled(LogLevel l) => true;
    public void Log<T>(LogLevel l, EventId e, T s, Exception? ex, Func<T, Exception?, string> f)
    { if (f != null) LogBuffer.Lines.Enqueue(f(s, ex)); }
}
