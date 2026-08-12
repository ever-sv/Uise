"""
Operator dashboard - what the network is doing and what it earned.

Served by the node itself from its own storage, with no external resources of any
kind: no CDN, no fonts, no scripts fetched from anywhere. A page that phones home
is a page that leaks who is running a node and how much it makes.

There is deliberately no button here that moves money. Balances and statements are
shown; payouts happen in the payment provider's own console, where the operator's
credentials already live and where the fraud controls already exist. Building a
withdrawal flow into this software would mean custodying funds, which is the one
thing the whole design exists to avoid.
"""

import html
import json
import time
from decimal import Decimal

from . import api

PATH_DASHBOARD = "/dashboard"

# Business data lives in the product API, never in the protocol namespace: one is
# Uise's own surface and may evolve, the other is a frozen standard.
PATH_STATS = api.PREFIX + "/stats"

_CHART_WIDTH = 640
_CHART_HEIGHT = 120


def stats(node, days=30):
    """Everything the dashboard shows, as plain JSON-serializable data."""
    storage = node.storage
    head = node.signed_tree_head()
    return {
        "issuer": {
            "did": node.did,
            "name": node.name,
            "suite": node.identity.suite.name,
            "long_term_evidence": node.identity.suite.long_term_evidence,
            "log": node.log_url,
            "fee": str(node.fee),
            "fee_unit": node.fee_unit,
        },
        "log": {
            "tree_size": head["tree_size"],
            "root": head["root"],
            "timestamp": head["timestamp"],
        },
        "totals": {
            "receipts": storage.log_size(),
            "revenue": storage.revenue(),
            "transacted_volume": storage.transacted_volume(),
            "transacting_agents": storage.active_agents(),
            "registered_agents": storage.registered_agents(),
            "registered_capabilities": storage.registered_capabilities(),
        },
        "credits": {
            # Prepaid money received but not yet earned. A liability, not revenue -
            # showing it as revenue would be lying to yourself about how much of
            # the bank balance is actually yours.
            "float_held": storage.float_held(),
            # Service consumed beyond what was funded: what customers owe.
            "outstanding": storage.outstanding(),
            "balances": storage.balances(),
        },
        "daily": storage.daily_usage(days),
        "top_capabilities": storage.top_capabilities(),
        # Who works with whom. A pair appears only because one agent paid the
        # other for real work, verified by three signatures.
        "graph": storage.agent_graph(),
        "accounts": storage.accounts(),
        "generated_at": int(time.time() * 1000),
    }


def _seed(session_token, graph):
    """
    Bootstrap data for the live layer, as inert JSON rather than generated code.

    Embedding values into a script body would mean any string in the data becomes
    executable if it escapes its quotes. A `application/json` block cannot be
    executed at all; `<` is escaped so the block cannot be closed early either.
    """
    payload = json.dumps({
        "token": session_token,
        "stream": api.PREFIX + "/events",
        "graph": [{"payer": edge["payer"], "payee": edge["payee"],
                   "receipts": edge["receipts"]} for edge in graph],
    }, ensure_ascii=False)
    return payload.replace("<", "\\u003c")


def _money(mapping):
    if not mapping:
        return "0"
    return "  ".join("%s %s" % (amount, unit) for unit, amount in sorted(mapping.items()))


def _bar_chart(daily):
    """Inline SVG bars. No script, no library, no request to anywhere."""
    points = [(row["day"], row["receipts"]) for row in daily]
    if not points:
        return '<p class="empty">No receipts issued yet.</p>'

    peak = max(count for _, count in points) or 1
    slot = _CHART_WIDTH / float(len(points))
    width = max(2.0, slot - 3)
    bars = []
    for index, (day, count) in enumerate(points):
        height = max(2.0, (count / float(peak)) * (_CHART_HEIGHT - 18))
        x = index * slot
        y = _CHART_HEIGHT - height
        bars.append(
            '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="2">'
            "<title>%s: %d</title></rect>"
            % (x, y, width, height, html.escape(day), count)
        )
    return (
        '<svg viewBox="0 0 %d %d" role="img" aria-label="Receipts per day" '
        'preserveAspectRatio="none">%s</svg>'
        '<div class="axis"><span>%s</span><span>peak %d/day</span><span>%s</span></div>'
        % (_CHART_WIDTH, _CHART_HEIGHT, "".join(bars),
           html.escape(points[0][0]), peak, html.escape(points[-1][0]))
    )


def _rows(items, columns, empty):
    if not items:
        return '<p class="empty">%s</p>' % html.escape(empty)
    head = "".join("<th>%s</th>" % html.escape(title) for title, _ in columns)
    body = []
    for item in items:
        cells = "".join("<td>%s</td>" % html.escape(str(getter(item))) for _, getter in columns)
        body.append("<tr>%s</tr>" % cells)
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (head, "".join(body))


STYLE = """
:root{--bg:#fbfbfa;--card:#fff;--ink:#1a1a19;--dim:#6b6b68;--line:#e6e6e3;--accent:#2f6f4f}
@media(prefers-color-scheme:dark){:root{--bg:#151514;--card:#1e1e1c;--ink:#f0efec;
--dim:#9a9a95;--line:#33332f;--accent:#7fc4a0}}
*{box-sizing:border-box}
body{margin:0;padding:32px 20px;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}
main{max-width:960px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--dim);
margin:32px 0 12px;font-weight:600}
.sub{color:var(--dim);font-size:13px;margin:0 0 28px;word-break:break-all}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card .label{font-size:12px;color:var(--dim);margin-bottom:6px}
.card .value{font-size:24px;font-weight:600;font-variant-numeric:tabular-nums}
.card .note{font-size:12px;color:var(--dim);margin-top:6px}
.accent .value{color:var(--accent)}
svg{width:100%;height:120px;display:block}
svg rect{fill:var(--accent);opacity:.85}
.axis{display:flex;justify-content:space-between;font-size:12px;color:var(--dim);margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-weight:600;font-size:12px;color:var(--dim);padding:8px 10px;
border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid var(--line);
font-variant-numeric:tabular-nums;word-break:break-all}
tr:last-child td{border-bottom:none}
.empty{color:var(--dim);font-size:14px;padding:12px 0;margin:0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.notice{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);
border-radius:8px;padding:14px 16px;font-size:13px;color:var(--dim);margin-top:12px}
.notice strong{color:var(--ink)}
footer{margin-top:36px;font-size:12px;color:var(--dim)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--dim);
border:1px solid var(--line);border-radius:999px;padding:3px 10px;vertical-align:middle}
.dot{width:7px;height:7px;border-radius:50%;background:var(--dim)}
.pill[data-state="live"] .dot{background:var(--accent)}
.pill[data-state="live"]{color:var(--accent);border-color:var(--border-accent,var(--line))}
.pill[data-state="retrying"] .dot{background:#c98a2e}
#graph{width:100%;height:320px;display:block;background:var(--card);
border:1px solid var(--line);border-radius:10px}
#graph line{stroke:var(--accent);opacity:.35}
#graph circle{fill:var(--accent);opacity:.85}
#graph text{fill:var(--dim);font-size:10px}
#feed{list-style:none;margin:0;padding:0;max-height:280px;overflow-y:auto;
border:1px solid var(--line);border-radius:10px;background:var(--card)}
#feed li{display:flex;gap:10px;padding:9px 14px;border-bottom:1px solid var(--line);
font-size:13px;align-items:baseline}
#feed li:last-child{border-bottom:none}
#feed .when{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums;
min-width:64px}
#feed .kind{color:var(--accent);font-size:12px;min-width:132px}
#feed .what{color:var(--ink);word-break:break-all}
"""


LIVE_SCRIPT = """
(function () {
  var seed = JSON.parse(document.getElementById("uise-seed").textContent);
  var pill = document.getElementById("status");
  var feed = document.getElementById("feed");
  var graph = document.getElementById("graph");
  var edges = seed.graph.slice();
  var lastEventId = null;
  var backoff = 1000;

  function setState(state, label) {
    pill.dataset.state = state;
    pill.lastElementChild.textContent = label;
  }

  function bump(id, delta) {
    var node = document.getElementById(id);
    if (!node) return;
    var current = Number(node.textContent.replace(/[^0-9]/g, "")) || 0;
    node.textContent = (current + delta).toLocaleString();
  }

  function shorten(did) {
    return did ? did.slice(0, 20) + "\\u2026" : "";
  }

  function record(event) {
    var item = document.createElement("li");
    var when = document.createElement("span");
    var kind = document.createElement("span");
    var what = document.createElement("span");
    when.className = "when";
    kind.className = "kind";
    what.className = "what";
    when.textContent = new Date(event.at).toLocaleTimeString();
    kind.textContent = event.type;
    what.textContent = describe(event);
    item.appendChild(when);
    item.appendChild(kind);
    item.appendChild(what);
    feed.insertBefore(item, feed.firstChild);
    while (feed.children.length > 60) feed.removeChild(feed.lastChild);
  }

  function describe(event) {
    var d = event.data || {};
    if (event.type === "receipt.issued")
      return shorten(d.payer) + " \\u2192 " + shorten(d.payee) +
             "  " + d.amount + " " + d.unit + "  (" + d.capability + ")";
    if (event.type === "agent.announced")
      return (d.name || shorten(d.agent)) + "  offers " +
             (d.capabilities || []).join(", ");
    if (event.type === "credit.deposited")
      return shorten(d.account) + "  +" + d.amount + " " + d.unit +
             "  balance " + d.balance;
    if (event.type === "credit.low")
      return shorten(d.account) + "  " + d.remaining_issuances + " issuances left";
    if (event.type === "stream.gap")
      return "events were missed; reload for exact figures";
    return JSON.stringify(d);
  }

  function remember(event) {
    if (event.type !== "receipt.issued") return;
    var d = event.data;
    for (var i = 0; i < edges.length; i++) {
      if (edges[i].payer === d.payer && edges[i].payee === d.payee) {
        edges[i].receipts += 1;
        return drawGraph();
      }
    }
    edges.push({ payer: d.payer, payee: d.payee, receipts: 1 });
    drawGraph();
  }

  function drawGraph() {
    var agents = [];
    edges.forEach(function (edge) {
      [edge.payer, edge.payee].forEach(function (did) {
        if (agents.indexOf(did) === -1) agents.push(did);
      });
    });
    var width = graph.clientWidth || 640;
    var height = 320;
    var radius = Math.min(width, height) / 2 - 34;
    var centreX = width / 2;
    var centreY = height / 2;
    var busiest = Math.max.apply(null, edges.map(function (e) { return e.receipts; }).concat([1]));
    var at = {};
    agents.forEach(function (did, index) {
      var angle = (index / agents.length) * Math.PI * 2 - Math.PI / 2;
      at[did] = [centreX + radius * Math.cos(angle), centreY + radius * Math.sin(angle)];
    });

    var parts = ['<svg viewBox="0 0 ' + width + ' ' + height + '" width="100%" height="' +
                 height + '" role="img" aria-label="Agents and the receipts between them">'];
    edges.forEach(function (edge) {
      var a = at[edge.payer], b = at[edge.payee];
      if (!a || !b) return;
      parts.push('<line x1="' + a[0].toFixed(1) + '" y1="' + a[1].toFixed(1) +
                 '" x2="' + b[0].toFixed(1) + '" y2="' + b[1].toFixed(1) +
                 '" stroke-width="' + (0.6 + 3 * edge.receipts / busiest).toFixed(2) + '"/>');
    });
    agents.forEach(function (did) {
      var point = at[did];
      var weight = edges.reduce(function (total, edge) {
        return total + (edge.payer === did || edge.payee === did ? edge.receipts : 0);
      }, 0);
      parts.push('<circle cx="' + point[0].toFixed(1) + '" cy="' + point[1].toFixed(1) +
                 '" r="' + (3 + 6 * weight / (busiest * 2)).toFixed(1) + '"><title>' +
                 did + ' \\u2014 ' + weight + ' receipts</title></circle>');
    });
    parts.push("</svg>");
    graph.innerHTML = parts.join("");
  }

  function apply(event) {
    lastEventId = event.seq || lastEventId;
    record(event);
    remember(event);
    if (event.type === "receipt.issued") bump("count-receipts", 1);
    if (event.type === "agent.announced") bump("count-registered", 1);
  }

  function connect() {
    var headers = { Authorization: "Bearer " + seed.token };
    if (lastEventId) headers["Last-Event-ID"] = String(lastEventId);
    setState("retrying", "connecting");

    fetch(seed.stream, { headers: headers }).then(function (response) {
      if (!response.ok) throw new Error("stream refused: " + response.status);
      setState("live", "live");
      backoff = 1000;
      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";
      return (function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) throw new Error("stream ended");
          buffer += decoder.decode(chunk.value, { stream: true });
          var frames = buffer.split("\\n\\n");
          buffer = frames.pop();
          frames.forEach(function (frame) {
            var payload = frame.split("\\n").filter(function (line) {
              return line.indexOf("data: ") === 0;
            })[0];
            if (payload) apply(JSON.parse(payload.slice(6)));
          });
          return pump();
        });
      })();
    }).catch(function () {
      setState("offline", "reconnecting");
      // The console must never hammer the node it is watching.
      backoff = Math.min(backoff * 2, 30000);
      setTimeout(connect, backoff);
    });
  }

  drawGraph();
  connect();
})();
"""


def render(data, session_token=None):
    """
    Render the console.

    The page is server-rendered with real values first, then the same page
    subscribes to the event stream and updates itself. That order matters: the
    numbers are correct the instant the page loads, and remain correct - though
    frozen - if scripting is unavailable. A console that shows nothing until
    JavaScript succeeds is a console that shows nothing when it matters most.
    """
    issuer = data["issuer"]
    totals = data["totals"]
    log_head = data["log"]

    revenue = _money(totals["revenue"])
    volume = _money(totals["transacted_volume"])
    take_rate = "-"
    for unit, earned in totals["revenue"].items():
        moved = Decimal(totals["transacted_volume"].get(unit, "0"))
        if moved > 0:
            take_rate = "%.3f%%" % (Decimal(earned) / moved * 100)
            break

    cards = [
        ("Receipts issued", "{:,}".format(totals["receipts"]),
         "Each one is a signed proof.", False, "count-receipts"),
        ("Uise revenue", revenue,
         "%s %s per receipt." % (issuer["fee"], issuer["fee_unit"]), True, None),
        ("Value transacted", volume,
         "Between agents. Uise never touches it.", False, None),
        ("Take rate", take_rate, "Revenue over volume.", False, None),
        ("Transacting agents", "{:,}".format(totals["transacting_agents"]),
         "Distinct payers and payees.", False, None),
        ("Registered agents", "{:,}".format(totals["registered_agents"]),
         "%s capabilities offered." % totals["registered_capabilities"], False,
         "count-registered"),
    ]
    card_html = "".join(
        '<div class="card%s"><div class="label">%s</div>'
        '<div class="value"%s>%s</div><div class="note">%s</div></div>'
        % (" accent" if accent else "", html.escape(label),
           ' id="%s"' % element_id if element_id else "",
           html.escape(value), html.escape(note))
        for label, value, note, accent, element_id in cards
    )

    daily_table = _rows(
        list(reversed(data["daily"]))[:14],
        [("Day", lambda r: r["day"]),
         ("Receipts", lambda r: r["receipts"]),
         ("Revenue", lambda r: "%s %s" % (r["fee_total"], r["unit"])),
         ("Volume", lambda r: "%s %s" % (r["volume_total"], r["unit"]))],
        "No usage recorded yet.",
    )
    capability_table = _rows(
        data["top_capabilities"],
        [("Capability", lambda r: r["capability"]), ("Receipts", lambda r: r["receipts"])],
        "No capabilities used yet.",
    )
    account_table = _rows(
        data["accounts"],
        [("Account", lambda r: r["label"]),
         ("Rail", lambda r: r["rail"]),
         ("Credit limit", lambda r: r["credit_limit"] if r["credit_limit"] is not None
          else "node policy"),
         ("Reference", lambda r: r["rail_ref"] or "-")],
        "No billing accounts registered yet.",
    )
    balance_table = _rows(
        data["credits"]["balances"],
        [("Account", lambda r: r["label"] or (r["account_id"][:28] + "...")),
         ("Balance", lambda r: "%s %s" % (r["amount"], r["unit"])),
         ("Limit", lambda r: r["credit_limit"] if r["credit_limit"] is not None
          else "node policy"),
         ("Status", lambda r: "funded" if Decimal(r["amount"]) > 0 else "owing")],
        "No balances yet.",
    )

    graph_table = _rows(
        data["graph"][:12],
        [("Payer", lambda r: r["payer"][:26] + "..."),
         ("Payee", lambda r: r["payee"][:26] + "..."),
         ("Receipts", lambda r: r["receipts"]),
         ("Volume", lambda r: "%s %s" % (r["volume"], r["unit"]))],
        "No agent pairs yet.",
    )

    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                              time.gmtime(data["generated_at"] / 1000))

    if session_token:
        # The live layer keeps the page current, so a blanket reload would only
        # throw away the stream and its position.
        refresh = ""
        live = ('<script type="application/json" id="uise-seed">%s</script>'
                "<script>%s</script>" % (_seed(session_token, data["graph"]),
                                         LIVE_SCRIPT))
        status = ('<span class="pill" id="status" data-state="offline">'
                  '<span class="dot"></span><span>connecting</span></span>')
    else:
        refresh = '<meta http-equiv="refresh" content="30">'
        live = ""
        status = ('<span class="pill"><span class="dot"></span>'
                  "<span>snapshot</span></span>")

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
%(refresh)s
<title>Uise node - %(name)s</title><style>%(style)s</style></head>
<body><main>
<h1>%(name)s %(status)s</h1>
<p class="sub mono">%(did)s</p>

<div class="grid">%(cards)s</div>

<h2>Live activity</h2>
<ul id="feed"><li><span class="when">-</span><span class="kind">waiting</span>
<span class="what">Events appear here as the node works.</span></li></ul>

<h2>The ecosystem</h2>
<div id="graph"></div>
%(pairs)s

<h2>Receipts per day</h2>
%(chart)s

<h2>Getting paid</h2>
<div class="grid">
<div class="card"><div class="label">Prepaid held</div><div class="value">%(float_held)s</div>
<div class="note">Received, not yet earned. A liability.</div></div>
<div class="card"><div class="label">Outstanding</div><div class="value">%(outstanding)s</div>
<div class="note">Consumed beyond funding. Owed to you.</div></div>
</div>
<div class="notice">
<strong>Uise bills for issuing proofs, and never holds anyone else's money.</strong>
The value transacted above moves directly between agents on their own rails.
Payouts of your revenue happen in your payment provider's console, where your
credentials and fraud controls already live - deliberately not here.
</div>
%(balances)s

<h2>Billing accounts</h2>
%(accounts)s

<h2>Daily detail</h2>
%(daily)s

<h2>Most used capabilities</h2>
%(capabilities)s

<h2>Transparency log</h2>
<div class="grid">
<div class="card"><div class="label">Tree size</div><div class="value">%(tree_size)s</div>
<div class="note">Entries, append-only.</div></div>
<div class="card"><div class="label">Signature suite</div><div class="value">%(suite)s</div>
<div class="note">%(evidence)s</div></div>
</div>
<p class="sub mono" style="margin-top:12px">root %(root)s</p>

<footer>Generated %(generated)s . <span class="mono">%(stats_path)s</span> for JSON,
<span class="mono">%(events_path)s</span> for the live stream.</footer>
%(live)s
</main></body></html>
""" % {
        "name": html.escape(issuer["name"]),
        "did": html.escape(issuer["did"]),
        "style": STYLE,
        "cards": card_html,
        "refresh": refresh,
        "status": status,
        "live": live,
        "pairs": graph_table,
        "events_path": api.PREFIX + "/events",
        "chart": _bar_chart(data["daily"]),
        "float_held": _money(data["credits"]["float_held"]),
        "outstanding": _money(data["credits"]["outstanding"]),
        "balances": balance_table,
        "accounts": account_table,
        "daily": daily_table,
        "capabilities": capability_table,
        "tree_size": "{:,}".format(log_head["tree_size"]),
        "suite": html.escape(issuer["suite"]),
        "evidence": ("Valid for permanent evidence."
                     if issuer["long_term_evidence"]
                     else "NOT valid for permanent evidence."),
        "root": html.escape(log_head["root"]),
        "generated": generated,
        "stats_path": PATH_STATS,
    }
