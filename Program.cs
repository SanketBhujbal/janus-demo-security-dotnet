// JANUS Demo .NET Security Target  (ASP.NET Core Minimal API)
// DO NOT DEPLOY
// 4 PCI-DSS vulns: 0=pan-cvv-logging 1=webhook-amount-trust 2=broken-authz-idor 3=missing-idempotency
// 0-2 -> VALIDATED  3 -> FAILED (test breaks after healer adds Idempotency-Key guard)
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
app.MapPost("/api/auth/login", async (HttpContext ctx, PaymentsStore db) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<LoginRequest>();
    var acc = db.Accounts.FirstOrDefault(a => a.Id == req?.Username && a.Password == req?.Password);
    if (acc is null) return Results.Unauthorized();
    var token = Guid.NewGuid().ToString("N");
    db.Tokens[token] = req!.Username!;
    return Results.Ok(new { token, username = req.Username });public class PaymentsStore {
    public List<Account>              Accounts        {get;}=new();
    public Dictionary<string, Order>  Orders          {get;}=new();
    public List<TxRecord>             Transactions    {get;}=new();
    public List<TxRecord>             ChargeHistory   {get;}=new();
    public Dictionary<string, string> Tokens          {get;}=new();
    public ConcurrentDictionary<string, (string TxId, decimal Amount)> IdempotencyStore {get;}=new();
}

app.MapPost("/api/payments/charge", async (HttpContext ctx, ILogger<Program> logger, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();
    var chargeReq = await ctx.Request.ReadFromJsonAsync<ChargeRequest>();
    var pan = chargeReq!.Pan ?? "";
    var maskedPan = pan.Length >= 10
        ? pan[..6] + new string('*', pan.Length - 10) + pan[^4..]
        : new string('*', pan.Length);
    logger.LogInformation("charge user={User} pan={Pan} amount={Amount}",
        db.Tokens[auth], maskedPan, chargeReq.Amount);
    var txId = Guid.NewGuid().ToString("N")[..16];
    db.ChargeHistory.Add(new TxRecord { Id = txId, User = db.Tokens[auth],
        Amount = chargeReq.Amount, Pan = chargeReq.Pan, Cvv = chargeReq.Cvv });
    return Results.Ok(new { transaction_id = txId, amount = chargeReq.Amount, status = "approved" });
});
app.MapGet("/api/payments/logs", () => Results.Text(string.Join(Environment.NewLine, LogBuffer.Lines)));
// VULN 1: webhook-amount-trust
app.MapPost("/api/webhook/gateway", async (HttpContext ctx, PaymentsStore db) =>
{
    var webhook = await ctx.Request.ReadFromJsonAsync<WebhookRequest>();
    if (!db.Orders.TryGetValue(webhook!.OrderId ?? "", out var order)) return Results.NotFound();

    if (order.Status == "settled") return Results.Conflict(new { error = "Order already settled" });

    if (webhook.Amount != order.Amount)
        return Results.BadRequest(new { error = "Amount mismatch: reconciliation failed" });

    order.Status = "settled";

    return Results.Ok(new { order.Id, order.Amount, order.Status });
});
app.MapGet("/api/payments/order/{id}", (string id, PaymentsStore db) =>
    db.Orders.TryGetValue(id, out var o) ? Results.Ok(new { o.Id, o.Amount, o.Status }) : Results.NotFound());
// VULN 2: broken-authz-idor
app.MapGet("/api/account/{id}", (string id, HttpContext ctx, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();

    var authenticatedUser = db.Tokens[auth];
    if (authenticatedUser != id) return Results.Forbid();

    var acc = db.Accounts.FirstOrDefault(x => x.Id == id);

    return acc is null ? Results.NotFound() : Results.Ok(new { acc.Id, acc.Balance });

});
// VULN 3: missing-idempotency
// EXPLOIT: POST /api/payments/transfer twice with same body — both calls succeed with DIFFERENT
//          transaction_ids proving replay is accepted. Print EXPLOIT_SUCCESS if tx1 != tx2.
app.MapPost("/api/payments/transfer", async (HttpContext ctx, PaymentsStore db) =>
{
    var auth = GetToken(ctx);
    if (auth is null || !db.Tokens.ContainsKey(auth)) return Results.Unauthorized();
    var req = await ctx.Request.ReadFromJsonAsync<TransferRequest>();
    var txId = Guid.NewGuid().ToString("N")[..16];
    db.Transactions.Add(new TxRecord { Id = txId, User = db.Tokens[auth], Amount = req!.Amount });
    return Results.Ok(new { transaction_id = txId, amount = req.Amount, status = "transferred" });
});
app.MapGet("/api/payments/transactions", (PaymentsStore db) =>
    Results.Ok(db.ChargeHistory.Concat(db.Transactions).Select(t => new { t.Id, t.User, t.Amount })));
app.Run();
static string? GetToken(HttpContext ctx) {
    var h = ctx.Request.Headers["Authorization"].ToString();
    return h.StartsWith("Bearer ") ? h[7..] : null;
}
public record LoginRequest(string? Username, string? Password);
public record ChargeRequest(decimal Amount, string? Pan, string? Cvv);
public record WebhookRequest(string? OrderId, decimal Amount, string? Signature);
public record TransferRequest(string? FromAccount, string? ToAccount, decimal Amount);
public class Account  { public string Id{get;set;}=""; public string Password{get;set;}=""; public decimal Balance{get;set;} }
public class Order    { public string Id{get;set;}=""; public decimal Amount{get;set;} public string Status{get;set;}=""; }
public class TxRecord { public string Id{get;set;}=""; public string User{get;set;}=""; public decimal Amount{get;set;} public string? Pan{get;set;} public string? Cvv{get;set;} }
public class PaymentsStore {
    public List<Account>              Accounts      {get;}=new();
    public Dictionary<string, Order>  Orders        {get;}=new();
    public List<TxRecord>             Transactions  {get;}=new();
    public List<TxRecord>             ChargeHistory {get;}=new();
    public Dictionary<string, string> Tokens        {get;}=new();
}
public static class LogBuffer { public static readonly ConcurrentQueue<string> Lines=new(); }
public class InMemoryLoggerProvider:ILoggerProvider{public ILogger CreateLogger(string c)=>new InMemoryLogger();public void Dispose(){}}
public class InMemoryLogger:ILogger{
    public IDisposable BeginScope<T>(T s)=>null!;
    public bool IsEnabled(LogLevel l)=>true;
    public void Log<T>(LogLevel l,EventId e,T s,Exception? ex,Func<T,Exception?,string> f){if(f!=null)LogBuffer.Lines.Enqueue(f(s,ex));}
}