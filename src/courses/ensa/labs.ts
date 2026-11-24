/** ENSA (Cisco Enterprise Networking, Security and Automation v7.0) — guided labs. Numbers follow ENSA_Modules_key_facts.md. */
import type { LabDef } from "@/lib/lab/types";
import { fmt } from "@/lib/utils";

const n = (v: unknown) => Number(v) || 0;
const clamp = (x: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, x));
const toInt = (o: number[]) => ((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3];
const toIp = (x: number) => [x / 16777216, x / 65536, x / 256, x].map((p) => Math.floor(p) % 256).join(".");
const maskOf = (p: number) => (p <= 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);
const bin = (x: number, w: number) => x.toString(2).padStart(w, "0");

/* ---------- OSPF ---------- */
const LINKS = [
  { value: "10", label: "Ethernet 10 Mbps", mbps: 10 },
  { value: "100", label: "FastEthernet 100 Mbps", mbps: 100 },
  { value: "1000", label: "Gigabit 1 Gbps", mbps: 1000 },
  { value: "10000", label: "10 Gigabit 10 Gbps", mbps: 10000 },
  { value: "1.544", label: "T1 serial 1.544 Mbps", mbps: 1.544 },
];
const ospfCost = (refMbps: number, bwMbps: number) => Math.max(1, Math.floor(refMbps / bwMbps));
const RNAMES = ["R1", "R2", "R3", "R4"];

/* ---------- ACL ---------- */
interface Ace { n: number; action: "permit" | "deny"; proto: string; src: [string, string]; dst: [string, string]; port?: number; text: string }
const ACL: Ace[] = [
  { n: 1, action: "permit", proto: "tcp", src: ["192.168.10.0", "0.0.0.255"], dst: ["0.0.0.0", "255.255.255.255"], port: 80, text: "permit tcp 192.168.10.0 0.0.0.255 any eq 80" },
  { n: 2, action: "permit", proto: "tcp", src: ["192.168.10.0", "0.0.0.255"], dst: ["0.0.0.0", "255.255.255.255"], port: 443, text: "permit tcp 192.168.10.0 0.0.0.255 any eq 443" },
  { n: 3, action: "permit", proto: "udp", src: ["192.168.10.0", "0.0.0.255"], dst: ["8.8.8.8", "0.0.0.0"], port: 53, text: "permit udp 192.168.10.0 0.0.0.255 host 8.8.8.8 eq 53" },
  { n: 4, action: "deny", proto: "tcp", src: ["0.0.0.0", "255.255.255.255"], dst: ["0.0.0.0", "255.255.255.255"], port: 23, text: "deny tcp any any eq 23" },
];
const ipNum = (s: string) => toInt(s.split(".").map(Number));
const wcMatch = (ip: string, [net, wc]: [string, string]) => (((ipNum(ip) ^ ipNum(net)) & ~ipNum(wc)) >>> 0) === 0;
const aceMatches = (a: Ace, src: string, dst: string, proto: string, port: number) =>
  a.proto === proto && wcMatch(src, a.src) && wcMatch(dst, a.dst) && (a.port === undefined || a.port === port);

/* ---------- PAT ---------- */
const groupOf = (p: number): [number, number] => (p < 512 ? [0, 511] : p < 1024 ? [512, 1023] : [1024, 65535]);
function patTable(hosts: number, port: number) {
  const [lo, hi] = groupOf(port), used = new Set<number>(), rows: { host: number; port: number | null }[] = [];
  let next = port;
  for (let i = 0; i < hosts; i++) {
    let got: number | null = null;
    if (!used.has(port)) got = port;
    else {
      // next available port in the same group, scanning upward from the last one handed out
      for (let k = 0, p = next; k < hi - lo + 1; k++, p = p >= hi ? lo : p + 1) if (!used.has(p)) { got = p; break; }
    }
    if (got !== null) { used.add(got); next = got >= hi ? lo : got + 1; }
    rows.push({ host: i, port: got });
  }
  return rows;
}
const hostIp = (i: number) => `192.168.${1 + Math.floor(i / 250)}.${(i % 250) + 1}`;

/* ---------- QoS ---------- */
const dscpOf = (v: Record<string, unknown>) =>
  v.dtype === "ef" ? 46 : v.dtype === "cs" ? 8 * n(v.csn) : v.dtype === "be" ? 0 : 8 * n(v.afClass) + 2 * n(v.afDrop);

export const labs: Record<string, LabDef> = {
  "ospf-config": {
    intro:
      "OSPF picks paths by cost, and cost is just reference bandwidth divided by interface bandwidth, floored, with a minimum of 1. Change the reference bandwidth and watch FastEthernet, Gigabit and 10 Gigabit links stop looking identical. Then run a DR/BDR election on a multiaccess segment and see why priority 0 can never win and why the router ID only breaks ties.",
    sections: [
      {
        id: "cost",
        title: "OSPF cost along a 3-hop path",
        blurb: "cost = reference bandwidth / interface bandwidth (integer, minimum 1). The path cost is the sum of the outgoing interface costs.",
        controls: [
          { kind: "select", id: "ref", label: "auto-cost reference-bandwidth", default: "100", options: [{ value: "100", label: "100 Mbps (default)" }, { value: "1000", label: "1000 Mbps" }, { value: "10000", label: "10000 Mbps" }] },
          { kind: "select", id: "l1", label: "Link 1 (R1-R2)", default: "10", options: LINKS.map(({ value, label }) => ({ value, label })) },
          { kind: "select", id: "l2", label: "Link 2 (R2-R3)", default: "100", options: LINKS.map(({ value, label }) => ({ value, label })) },
          { kind: "select", id: "l3", label: "Link 3 (R3-R4)", default: "1.544", options: LINKS.map(({ value, label }) => ({ value, label })) },
        ],
        derive: (v) => {
          const ref = n(v.ref), bws = [n(v.l1), n(v.l2), n(v.l3)], costs = bws.map((b) => ospfCost(ref, b));
          const fe = bws.indexOf(100), ge = bws.indexOf(1000);
          return {
            c1: costs[0], c2: costs[1], c3: costs[2], total: costs[0] + costs[1] + costs[2],
            feGeSame: fe >= 0 && ge >= 0 && costs[fe] === costs[ge],
          };
        },
        view: (v, d) => {
          const names = [v.l1, v.l2, v.l3].map((x) => LINKS.find((l) => l.value === x)?.label ?? String(x));
          const costs = [n(d.c1), n(d.c2), n(d.c3)];
          let run = 0;
          const rows = costs.map((c, i) => { run += c; return [`Link ${i + 1}`, names[i], `${n(v.ref)} / ${n([v.l1, v.l2, v.l3][i])} = ${c}`, run]; });
          return [
            { kind: "table", head: ["Link", "Type", "Cost", "Cumulative"], rows },
            { kind: "stats", items: [{ label: "Path cost R1 → R4", value: n(d.total), tone: "accent" }, { label: "Reference bandwidth", value: `${fmt(n(v.ref))} Mbps` }] },
            { kind: "note", text: d.feGeSame ? "FastEthernet and Gigabit cost the same: with a 100 Mbps reference everything at or above 100 Mbps floors to **1**, so OSPF cannot tell them apart." : "Raise the reference bandwidth on every router so faster links get smaller costs than slower ones.", tone: d.feGeSame ? "warn" : "neutral" },
          ];
        },
        code: `router ospf 10
 auto-cost reference-bandwidth 10000   ! Mbps; set the same value on every router
!
interface GigabitEthernet0/0/0
 ip ospf cost 10                       ! or override the cost by hand
interface Serial0/1/0
 bandwidth 1544                        ! kbps; the metric uses this value
R1# show ip ospf interface brief`,
      },
      {
        id: "dr",
        title: "DR / BDR election on a multiaccess segment",
        blurb: "Highest priority wins, then highest router ID. Priority 0 means the router never takes part. Ties in both are impossible with unique router IDs.",
        controls: [
          ...[1, 2, 3, 4].flatMap((i) => [
            { kind: "number" as const, id: `p${i}`, label: `R${i} priority`, default: 1, min: 0, max: 255 },
            { kind: "number" as const, id: `rid${i}`, label: `R${i} router ID (n.n.n.n)`, default: i, min: 1, max: 254 },
          ]),
        ],
        derive: (v) => {
          const rs = [1, 2, 3, 4].map((i) => ({ i, p: clamp(n(v[`p${i}`]), 0, 255), rid: n(v[`rid${i}`]) }));
          const order = rs.filter((r) => r.p > 0).sort((a, b) => b.p - a.p || b.rid - a.rid || b.i - a.i);
          const dr = order[0]?.i ?? 0, bdr = order[1]?.i ?? 0;
          return { dr, bdr, drName: dr ? `R${dr}` : "none", bdrName: bdr ? `R${bdr}` : "none", others: rs.filter((r) => r.i !== dr && r.i !== bdr).map((r) => `R${r.i}`).join(", ") || "none" };
        },
        view: (v, d) => [
          {
            kind: "table",
            head: ["Router", "Priority", "Router ID", "Role"],
            rows: RNAMES.map((nm, k) => [nm, clamp(n(v[`p${k + 1}`]), 0, 255), `${n(v[`rid${k + 1}`])}.${n(v[`rid${k + 1}`])}.${n(v[`rid${k + 1}`])}.${n(v[`rid${k + 1}`])}`, d.dr === k + 1 ? "DR" : d.bdr === k + 1 ? "BDR" : "DROTHER"]),
            highlight: [[n(d.dr) - 1, 3], [n(d.bdr) - 1, 3]].filter(([r]) => r >= 0) as [number, number][],
          },
          { kind: "stats", items: [{ label: "DR", value: String(d.drName), tone: "good" }, { label: "BDR", value: String(d.bdrName), tone: "accent" }, { label: "DROTHERs", value: String(d.others) }] },
        ],
        code: `interface GigabitEthernet0/0/0
 ip ospf priority 255     ! 0 = never DR/BDR; default is 1
R1# show ip ospf neighbor ! State column shows FULL/DR, FULL/BDR, 2WAY/DROTHER
R1# clear ip ospf process ! needed to force a new election (it is non-preemptive)`,
      },
    ],
    tasks: [
      { kind: "predict", id: "p-t1", prompt: "With the default 100 Mbps reference bandwidth, what OSPF cost does a T1 (1.544 Mbps) serial link get?", answer: 64, tolerance: 0, explain: "100 / 1.544 = 64.77, floored to 64. Gigabit and 10 Gigabit links floor 100/1000 = 0.1 up to the minimum of 1." },
      { kind: "goal", id: "g-fe-ge", prompt: "Make a FastEthernet link and a Gigabit link have the same OSPF cost. Which reference bandwidth does it?", hint: "Put one FastEthernet and one Gigabit link on the path and try each reference value.", check: (v, d) => Boolean(d.feGeSame) },
      { kind: "goal", id: "g-big", prompt: "Push the 3-hop path cost above 10,000.", hint: "Slow links with a large reference bandwidth: 10000 / 1.544 = 6476.", check: (_, d) => n(d.total) > 10000 },
      { kind: "goal", id: "g-r3dr", prompt: "Make R3 the DR.", hint: "Give R3 the highest priority, or tie on priority and give it the highest router ID.", check: (_, d) => n(d.dr) === 3 },
      { kind: "explain", id: "e-ospf", prompt: "Why must the reference bandwidth be set on every OSPF router, and why can a router with priority 0 never become DR?", keywords: ["reference bandwidth", "cost", "gigabit", "consistent", "priority 0", "DR", "BDR", "router ID", "multiaccess", "non-preemptive"], idealAnswer: "Cost is reference bandwidth divided by interface bandwidth, so every router must use the same reference or the same link gets different costs and SPF paths disagree; a larger reference also stops FastEthernet, Gigabit and 10 Gigabit all collapsing to cost 1. On a multiaccess segment the DR and BDR cut the number of adjacencies and LSA flooding. The election picks the highest priority, then the highest router ID; priority 0 removes a router from the election entirely, and since it is non-preemptive a later, better router does not replace an existing DR until the process is reset." },
    ],
    daily: (r, date) => {
      const ref = r.pick([100, 1000, 10000]), bw = r.pick([10, 100, 1000, 10000, 1.544]), cost = ospfCost(ref, bw);
      return { title: `OSPF cost · ${date}`, question: `With <code>auto-cost reference-bandwidth ${ref}</code>, what is the OSPF cost of a <b>${bw} Mbps</b> interface?`, answer: cost, tolerance: 0, hint: "Divide, floor, minimum 1.", explanation: `${ref} / ${bw} = ${fmt(ref / bw)}, floored with a minimum of 1 gives ${cost}.` };
    },
  },

  acls: {
    intro:
      "Wildcard masks are the inverse of subnet masks: 0 means 'must match', 1 means 'ignore'. Convert a prefix length into its wildcard and the exact range of addresses it matches, then fire packets at a four-line extended ACL and see which line catches them first, or whether the implicit deny at the end does.",
    sections: [
      {
        id: "wildcard",
        title: "Wildcard mask calculator",
        blurb: "wildcard = 255.255.255.255 - subnet mask.",
        controls: [
          { kind: "range", id: "plen", label: "Prefix length", min: 8, max: 32, default: 24, unit: "bits", format: (x) => `/${x}` },
          { kind: "number", id: "o1", label: "Network octet 1", default: 192, min: 0, max: 255 },
          { kind: "number", id: "o2", label: "Network octet 2", default: 168, min: 0, max: 255 },
          { kind: "number", id: "o3", label: "Network octet 3", default: 10, min: 0, max: 255 },
          { kind: "number", id: "o4", label: "Network octet 4", default: 0, min: 0, max: 255 },
        ],
        derive: (v) => {
          const p = clamp(Math.round(n(v.plen)), 0, 32), mask = maskOf(p), wild = (~mask) >>> 0;
          const ip = toInt([n(v.o1), n(v.o2), n(v.o3), n(v.o4)]), net = (ip & mask) >>> 0, last = (net | wild) >>> 0;
          return { mask: toIp(mask), wc: toIp(wild), hostsMatched: 2 ** (32 - p), net: toIp(net), first: toIp(net), last: toIp(last) };
        },
        view: (v, d) => [
          { kind: "result", label: "Wildcard mask", value: String(d.wc), work: `/${n(v.plen)} → subnet mask ${d.mask}\n255.255.255.255 - ${d.mask} = ${d.wc}`, tone: "accent" },
          { kind: "stats", items: [{ label: "Addresses matched", value: fmt(n(d.hostsMatched)) }, { label: "Network", value: String(d.net) }, { label: "Range", value: `${d.first} – ${d.last}` }] },
          { kind: "note", text: `ACE fragment: **${d.net} ${d.wc}** matches ${fmt(n(d.hostsMatched))} address${n(d.hostsMatched) === 1 ? "" : "es"}. A /32 is the keyword **host** (0.0.0.0); 0.0.0.0 with 255.255.255.255 is **any**.` },
        ],
        code: `R1(config)# access-list 10 permit 192.168.10.0 0.0.0.255
R1(config)# access-list 10 permit 192.168.16.0 0.0.15.255   ! 192.168.16.0 - 192.168.31.255
R1(config)# access-list 10 permit host 192.168.10.50        ! same as 192.168.10.50 0.0.0.0`,
      },
      {
        id: "eval",
        title: "Extended ACL evaluator",
        blurb: "ACEs are checked top to bottom; the first match decides. A packet that matches nothing hits the implicit deny.",
        controls: [
          { kind: "select", id: "src", label: "Source", default: "192.168.10.25", options: [{ value: "192.168.10.25", label: "192.168.10.25 (PC1)" }, { value: "192.168.10.50", label: "192.168.10.50" }, { value: "192.168.20.5", label: "192.168.20.5 (other LAN)" }, { value: "172.16.0.9", label: "172.16.0.9 (outside)" }] },
          { kind: "select", id: "dst", label: "Destination", default: "203.0.113.10", options: [{ value: "203.0.113.10", label: "203.0.113.10 (web server)" }, { value: "8.8.8.8", label: "8.8.8.8 (DNS)" }, { value: "198.51.100.7", label: "198.51.100.7" }] },
          { kind: "select", id: "proto", label: "Protocol", default: "tcp", options: [{ value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }, { value: "icmp", label: "ICMP" }] },
          { kind: "select", id: "port", label: "Destination port", default: "80", options: ["22", "23", "53", "80", "443", "3389"].map((p) => ({ value: p, label: p })) },
        ],
        derive: (v) => {
          const hit = ACL.find((a) => aceMatches(a, String(v.src), String(v.dst), String(v.proto), n(v.port)));
          return { hit: hit?.n ?? 0, verdict: hit ? hit.action : "deny (implicit)", implicit: !hit };
        },
        view: (v, d) => {
          const proto = String(v.proto);
          return [
            {
              kind: "table",
              head: ["ACE", "Rule", "Match?"],
              rows: [...ACL.map((a) => [a.n * 10, a.text, aceMatches(a, String(v.src), String(v.dst), proto, n(v.port)) ? (d.hit === a.n ? "MATCH - stop" : "matches (not reached)") : "no"]), ["-", "deny ip any any (implicit, invisible)", d.implicit ? "MATCH" : "not reached"]],
              highlight: [[d.implicit ? 4 : n(d.hit) - 1, 2]],
            },
            { kind: "result", label: "Verdict", value: d.implicit ? "DENIED by the implicit deny" : `${String(d.verdict).toUpperCase()} by ACE ${n(d.hit) * 10}`, tone: d.verdict === "permit" ? "good" : "bad", work: `${v.src} → ${v.dst} ${proto}${proto === "icmp" ? "" : `/${v.port}`}` },
          ];
        },
        code: `ip access-list extended OUTBOUND
 10 permit tcp 192.168.10.0 0.0.0.255 any eq 80
 20 permit tcp 192.168.10.0 0.0.0.255 any eq 443
 30 permit udp 192.168.10.0 0.0.0.255 host 8.8.8.8 eq 53
 40 deny tcp any any eq 23
!                          ! implicit: deny ip any any
interface GigabitEthernet0/0/1
 ip access-group OUTBOUND in`,
      },
    ],
    tasks: [
      { kind: "predict", id: "p-wild", prompt: "How many addresses does the wildcard mask 0.0.0.31 match?", answer: 32, tolerance: 0, unit: "addresses", explain: "A wildcard of 0.0.0.31 ignores the last 5 bits, so 2^5 = 32 addresses (a /27)." },
      { kind: "goal", id: "g-wc15", prompt: "Produce the wildcard mask 0.0.15.255 and read off the range it matches.", hint: "0.0.15.255 ignores 12 bits, so the prefix is /20.", check: (_, d) => d.wc === "0.0.15.255" },
      { kind: "goal", id: "g-implicit", prompt: "Send a packet that falls through to the implicit deny.", hint: "Try a source outside 192.168.10.0/24 on a port the ACL never names.", check: (_, d) => Boolean(d.implicit) },
      { kind: "goal", id: "g-ace3", prompt: "Make ACE 30 the first match.", hint: "It is the DNS rule: UDP 53 to 8.8.8.8 from 192.168.10.x.", check: (_, d) => n(d.hit) === 3 },
      { kind: "explain", id: "e-acl", prompt: "Why does ACE order matter, and what happens to a packet that matches none of the ACEs?", keywords: ["top-down", "first match", "specific", "general", "implicit deny", "wildcard", "order", "deny ip any any"], idealAnswer: "An ACL is processed top to bottom and the first matching ACE decides, so specific entries must come before general ones or they are shadowed and never reached. A packet that matches nothing is dropped by the invisible implicit deny ip any any at the end, so an ACL with only deny lines blocks everything; add a permit for the traffic you want." },
    ],
    daily: (r, date) => {
      const p = r.int(25, 30);
      return { title: `Wildcard mask · ${date}`, question: `What is the <b>fourth octet</b> of the wildcard mask for a <b>/${p}</b> network (<code>0.0.0.?</code>)?`, answer: 2 ** (32 - p) - 1, tolerance: 0, hint: "255 minus the last octet of the subnet mask.", explanation: `The subnet mask's last octet is ${256 - 2 ** (32 - p)}, so the wildcard is 255 - ${256 - 2 ** (32 - p)} = ${2 ** (32 - p) - 1}.` };
    },
  },

  nat: {
    intro:
      "PAT lets many inside hosts share one public address by tracking the source port. Have a crowd of hosts all pick the same source port and watch the router keep the first one and shuffle the rest within the same port group, until the group runs dry. Then compare that with dynamic NAT, where every simultaneous host needs a public address of its own.",
    sections: [
      {
        id: "pat",
        title: "PAT (NAT overload) translation table",
        blurb: "PAT tries to keep the original source port; if it is taken it uses the next available port in the same group (0-511, 512-1023, 1024-65535).",
        controls: [
          { kind: "range", id: "hosts", label: "Inside hosts", min: 1, max: 600, default: 4 },
          { kind: "select", id: "sport", label: "Source port used by every host", default: "80", options: [{ value: "80", label: "80 (group 0-511)" }, { value: "443", label: "443 (group 0-511)" }, { value: "600", label: "600 (group 512-1023)" }, { value: "1444", label: "1444 (group 1024-65535)" }, { value: "5000", label: "5000 (group 1024-65535)" }] },
        ],
        derive: (v) => {
          const rows = patTable(Math.round(n(v.hosts)), n(v.sport)), ok = rows.filter((r) => r.port !== null);
          return { translated: ok.length, failed: rows.length - ok.length, port2: rows[1]?.port ?? 0, lastPort: ok.length ? Number(ok[ok.length - 1].port) : 0, group: groupOf(n(v.sport)).join("-") };
        },
        view: (v, d) => {
          const rows = patTable(Math.round(n(v.hosts)), n(v.sport)), shown = rows.slice(0, 8);
          return [
            { kind: "table", title: "Show ip nat translations (first 8)", head: ["Inside local", "Inside global", "Port changed?"], rows: shown.map((r) => [`${hostIp(r.host)}:${v.sport}`, r.port === null ? "no port left" : `209.165.200.225:${r.port}`, r.port === null ? "-" : r.port === n(v.sport) ? "no" : "yes"]) },
            { kind: "stats", items: [{ label: "Translated", value: fmt(n(d.translated)), tone: "good" }, { label: "No port left", value: fmt(n(d.failed)), tone: n(d.failed) ? "bad" : "good" }, { label: "Port group", value: String(d.group) }] },
            { kind: "note", text: n(d.failed) ? "The port group is exhausted. With a pool, the router would move to the next pool address; with one address, the extra hosts get no translation." : "One public address is serving every host, told apart only by the port.", tone: n(d.failed) ? "warn" : "neutral" },
          ];
        },
        code: `R2(config)# access-list 1 permit 192.168.0.0 0.0.255.255
R2(config)# ip nat inside source list 1 interface serial0/1/1 overload
R2(config)# interface g0/0/0
R2(config-if)# ip nat inside
R2(config)# interface s0/1/1
R2(config-if)# ip nat outside
R2# show ip nat translations`,
      },
      {
        id: "pool",
        title: "Dynamic NAT pool vs simultaneous hosts",
        blurb: "Each active inside host holds one public address from the pool. Hosts beyond the pool size have to wait.",
        controls: [
          { kind: "number", id: "first", label: "Pool first address (209.165.200.x)", default: 226, min: 1, max: 254 },
          { kind: "number", id: "last", label: "Pool last address (209.165.200.x)", default: 240, min: 1, max: 254 },
          { kind: "range", id: "simul", label: "Simultaneous inside hosts", min: 1, max: 60, default: 20 },
        ],
        derive: (v) => {
          const size = Math.max(0, n(v.last) - n(v.first) + 1), hosts = n(v.simul), translated = Math.min(size, hosts);
          return { poolSize: size, poolTranslated: translated, waiting: hosts - translated };
        },
        view: (v, d) => [
          { kind: "result", label: "Pool", value: `209.165.200.${n(v.first)} – 209.165.200.${n(v.last)} (${n(d.poolSize)} addresses)`, work: `${n(v.last)} - ${n(v.first)} + 1 = ${n(d.poolSize)}` },
          { kind: "bars", items: [{ label: "Translated", value: n(d.poolTranslated), max: Math.max(1, n(v.simul)), display: String(d.poolTranslated), tone: "good" }, { label: "Waiting (no free address)", value: n(d.waiting), max: Math.max(1, n(v.simul)), display: String(d.waiting), tone: n(d.waiting) ? "bad" : "good" }] },
        ],
        code: `R2(config)# ip nat pool NAT-POOL1 209.165.200.226 209.165.200.240 netmask 255.255.255.224
R2(config)# access-list 1 permit 192.168.0.0 0.0.255.255
R2(config)# ip nat inside source list 1 pool NAT-POOL1`,
      },
    ],
    tasks: [
      { kind: "predict", id: "p-port", prompt: "Four inside hosts all use source port 1444 through one PAT address. Which port does the third host get?", answer: 1446, tolerance: 0, explain: "Host 1 keeps 1444, host 2 gets the next free port 1445, host 3 gets 1446 (host 4 would get 1447)." },
      { kind: "goal", id: "g-1445", prompt: "Reproduce the textbook case: two hosts on port 1444, the second translated to 1445.", hint: "Pick source port 1444 and at least 2 hosts.", check: (v, d) => n(v.sport) === 1444 && n(d.port2) === 1445 },
      { kind: "goal", id: "g-exhaust", prompt: "Run a port group out of ports so some hosts cannot be translated.", hint: "The 0-511 group has only 512 ports.", check: (_, d) => n(d.failed) > 0 },
      { kind: "goal", id: "g-pool", prompt: "Resize the pool so 30 or more simultaneous hosts are all translated and nobody waits.", hint: "Widen the first-last range to at least as many addresses as hosts.", check: (v, d) => n(v.simul) >= 30 && n(d.waiting) === 0 },
      { kind: "explain", id: "e-pat", prompt: "Explain how PAT lets many hosts share one address, and why dynamic NAT needs a bigger pool.", keywords: ["port", "overload", "many-to-one", "source port", "pool", "simultaneous", "first-come", "translation table", "same group"], idealAnswer: "PAT (NAT overload) is many-to-one: it rewrites both the address and the source port and records each pair in the translation table, so replies can be mapped back. It tries to keep the original port and otherwise picks the next free port in the same group (0-511, 512-1023, 1024-65535). Dynamic NAT only rewrites the address, first-come-first-served, so each simultaneous host needs its own public address and the pool must be as large as the number of concurrent sessions." },
    ],
    daily: (r, date) => {
      const first = r.int(225, 235), size = r.int(6, 20), hosts = size + r.int(1, 15);
      return { title: `NAT pool · ${date}`, question: `A dynamic NAT pool runs from <b>209.165.200.${first}</b> to <b>209.165.200.${first + size - 1}</b>. With <b>${hosts}</b> hosts active at once, how many must wait for an address?`, answer: hosts - size, tolerance: 0, hint: "Pool size = last - first + 1.", explanation: `Pool size = ${first + size - 1} - ${first} + 1 = ${size}; ${hosts} - ${size} = ${hosts - size} wait.` };
    },
  },

  "qos-management": {
    intro:
      "QoS markings are bit patterns. Build a DSCP value from an AF class and drop precedence, see its six bits and the class-selector bits that old devices read as CoS or IP precedence, then spend a one-way delay budget for a voice call and see how quickly the 150 ms limit disappears.",
    sections: [
      {
        id: "dscp",
        title: "DSCP calculator",
        blurb: "AFxy: DSCP = 8x + 2y. EF = 46. Class selector CSn = 8n.",
        controls: [
          { kind: "select", id: "dtype", label: "Marking", default: "af", options: [{ value: "af", label: "AF (assured forwarding)" }, { value: "ef", label: "EF (expedited forwarding)" }, { value: "cs", label: "CS (class selector)" }, { value: "be", label: "BE (default)" }] },
          { kind: "select", id: "afClass", label: "AF class x (4 = best)", default: "1", options: ["1", "2", "3", "4"].map((x) => ({ value: x, label: `AF${x}y` })) },
          { kind: "select", id: "afDrop", label: "Drop precedence y (3 = dropped first)", default: "1", options: ["1", "2", "3"].map((x) => ({ value: x, label: `AFx${x}` })) },
          { kind: "range", id: "csn", label: "CS number n", min: 0, max: 7, default: 1, format: (x) => `CS${x}` },
        ],
        derive: (v) => {
          const dscp = dscpOf(v), b = bin(dscp, 6), name = v.dtype === "ef" ? "EF" : v.dtype === "cs" ? `CS${n(v.csn)}` : v.dtype === "be" ? "BE" : `AF${n(v.afClass)}${n(v.afDrop)}`;
          return { dscp, bits: b, name, csBits: b.slice(0, 3), cos: dscp >> 3, dropBits: b.slice(3, 5) };
        },
        view: (v, d) => [
          { kind: "result", label: `${d.name} → DSCP`, value: `${d.dscp}  (${d.bits})`, tone: "accent", work: v.dtype === "af" ? `8 × ${v.afClass} + 2 × ${v.afDrop} = ${d.dscp}` : v.dtype === "cs" ? `8 × ${v.csn} = ${d.dscp}` : `${d.name} = ${d.dscp}` },
          { kind: "stats", items: [{ label: "Class selector bits", value: String(d.csBits) }, { label: "Maps to CoS / IPP", value: n(d.cos) }, { label: "Drop-preference bits", value: String(d.dropBits) }] },
          { kind: "note", text: "The six DSCP bits sit in the top six bits of the 8-bit ToS / Traffic Class byte; the last two are ECN. EF (46 = 101110) maps to CoS 5 and is for voice only." },
        ],
        code: `class-map match-all VOICE
 match ip dscp ef
class-map match-all CRITICAL
 match ip dscp af31 af32 af33
policy-map MARK-IN
 class CRITICAL
  set dscp af32          ! AF32 = 011100 = 28`,
      },
      {
        id: "delay",
        title: "One-way voice delay budget",
        blurb: "Voice needs under 150 ms one way (jitter under 30 ms, loss under 1%). Every stage spends part of it.",
        controls: [
          { kind: "select", id: "codec", label: "Codec processing", default: "5", options: [{ value: "5", label: "G.711 (about 5 ms)" }, { value: "25", label: "G.729 (about 25 ms)" }, { value: "40", label: "Low-bit-rate codec (about 40 ms)" }] },
          { kind: "range", id: "pack", label: "Packetization (voice per packet)", min: 10, max: 60, step: 10, default: 20, unit: "ms" },
          { kind: "range", id: "bytes", label: "Packet size", min: 64, max: 1500, step: 4, default: 200, unit: "bytes" },
          { kind: "select", id: "kbps", label: "Slowest link speed", default: "1544", options: [{ value: "64", label: "64 kbps" }, { value: "128", label: "128 kbps" }, { value: "1544", label: "T1 1.544 Mbps" }, { value: "100000", label: "100 Mbps" }] },
          { kind: "range", id: "km", label: "Distance", min: 0, max: 20000, step: 500, default: 1000, unit: "km" },
          { kind: "range", id: "queue", label: "Queuing delay", min: 0, max: 100, step: 5, default: 10, unit: "ms" },
          { kind: "range", id: "jit", label: "De-jitter buffer", min: 10, max: 100, step: 5, default: 40, unit: "ms" },
        ],
        derive: (v) => {
          const ser = (n(v.bytes) * 8) / n(v.kbps), prop = n(v.km) * 0.005;
          const total = n(v.codec) + n(v.pack) + ser + prop + n(v.queue) + n(v.jit);
          return { ser, prop, total, headroom: 150 - total, over: total > 150 };
        },
        view: (v, d) => {
          const max = Math.max(150, n(d.total));
          return [
            { kind: "bars", items: [
              { label: "Codec", value: n(v.codec), max, display: `${n(v.codec)} ms` },
              { label: "Packetization", value: n(v.pack), max, display: `${n(v.pack)} ms` },
              { label: "Serialization", value: n(d.ser), max, display: `${n(d.ser).toFixed(2)} ms` },
              { label: "Propagation", value: n(d.prop), max, display: `${n(d.prop).toFixed(1)} ms` },
              { label: "Queuing", value: n(v.queue), max, display: `${n(v.queue)} ms` },
              { label: "De-jitter buffer", value: n(v.jit), max, display: `${n(v.jit)} ms` },
            ] },
            { kind: "result", label: "One-way delay", value: `${n(d.total).toFixed(1)} ms of 150 ms`, tone: d.over ? "bad" : "good", work: `serialization = ${v.bytes} B × 8 / ${v.kbps} kbps = ${n(d.ser).toFixed(2)} ms\npropagation ≈ ${v.km} km × 5 µs/km = ${n(d.prop).toFixed(1)} ms` },
            { kind: "note", text: d.over ? "Over budget: callers will talk over each other. Fix the biggest bar: queue voice first (LLQ) and shrink packets on slow links." : `${n(d.headroom).toFixed(1)} ms of headroom left.`, tone: d.over ? "bad" : "good" },
          ];
        },
        code: `policy-map WAN-OUT
 class VOICE
  priority percent 20     ! LLQ: strict-priority queue keeps voice queuing near zero
 class CRITICAL
  bandwidth percent 30
interface Serial0/1/0
 service-policy output WAN-OUT`,
      },
    ],
    tasks: [
      { kind: "predict", id: "p-af21", prompt: "What is the decimal DSCP value of AF21?", answer: 18, tolerance: 0, explain: "DSCP = 8x + 2y = 8 × 2 + 2 × 1 = 18, binary 010010." },
      { kind: "goal", id: "g-28", prompt: "Produce DSCP 28 (AF32).", hint: "Class 3, drop precedence 2: 8 × 3 + 2 × 2.", check: (_, d) => n(d.dscp) === 28 },
      { kind: "goal", id: "g-over", prompt: "Exceed the 150 ms one-way voice delay target.", hint: "Slow link, big packets, long distance or heavy queuing all add up.", check: (_, d) => n(d.total) > 150 },
      { kind: "goal", id: "g-far", prompt: "Carry voice at least 10,000 km and still stay under 150 ms.", hint: "Propagation alone costs 50 ms; keep queuing and the de-jitter buffer small.", check: (v, d) => n(v.km) >= 10000 && n(d.total) <= 150 },
      { kind: "explain", id: "e-qos", prompt: "Why is voice marked EF and queued in an LLQ, and what are the limits for one-way delay, jitter and loss?", keywords: ["EF", "46", "LLQ", "priority queue", "150 ms", "jitter", "30 ms", "loss", "1%", "congestion", "mark near the source"], idealAnswer: "Voice is UDP, smooth and very sensitive to delay and drops, so it is marked EF (DSCP 46, CoS 5) as close to the source as possible and placed in the strict-priority queue of LLQ, which keeps its queuing delay minimal. Targets are under 150 ms one-way latency, under 30 ms jitter and under 1% loss. QoS only matters during congestion, when queues build and delay or drops appear." },
    ],
    daily: (r, date) => {
      const x = r.int(1, 4), y = r.int(1, 3);
      return { title: `DSCP · ${date}`, question: `What is the decimal DSCP value of <b>AF${x}${y}</b>?`, answer: 8 * x + 2 * y, tolerance: 0, hint: "DSCP = 8x + 2y.", explanation: `8 × ${x} + 2 × ${y} = ${8 * x + 2 * y} (binary ${bin(8 * x + 2 * y, 6)}).` };
    },
  },
};
