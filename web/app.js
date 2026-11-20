const $ = (id) => document.getElementById(id);
let data = null;
let relays = [];
let busy = false;
let timer = 0;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

async function api(path, body) {
  const res = await fetch(path, body == null ? undefined : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = null; }
  }
  if (res.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error("Sign in.");
  }
  if (!res.ok) throw new Error((payload && payload.error) || "Request failed");
  return payload;
}

function showLogin() {
  $("boot").hidden = true;
  $("login").hidden = false;
  $("app").hidden = true;
  clearInterval(timer);
}

function showApp() {
  $("boot").hidden = true;
  $("login").hidden = true;
  $("app").hidden = false;
  showPage();
}

function flash(msg) {
  const n = $("flash");
  n.textContent = msg || "";
}

function dotClass(d) {
  if (d.blocked) return "r";
  if (d.online) return "";
  if (d.lease && d.lease !== "—" && d.lease !== "Expired") return "w";
  return "o";
}

function statusLabel(d) {
  if (d.blocked) return "Blocked";
  if (d.online) return "Online";
  if (d.lease && d.lease !== "—" && d.lease !== "Expired") return "Idle";
  return "Offline";
}

function renderDevices() {
  const q = ($("q").value || "").toLowerCase();
  const body = $("rows");
  body.replaceChildren();
  const list = (data.devices || []).filter((d) => d.online && (d.name + " " + d.ip + " " + d.mac).toLowerCase().includes(q));
  if (!list.length) {
    const tr = document.createElement("tr");
    const connected = (data.devices || []).some((d) => d.online);
    const td = el("td", "empty", connected ? "No matches." : "Nobody is connected right now.");
    td.colSpan = 9;
    tr.append(td);
    body.append(tr);
    return;
  }
  for (const d of list) {
    const tr = document.createElement("tr");
    tr.append(el("td", "", d.name), linkCell(d.source), el("td", "mono", d.ip), el("td", "mono", d.mac), el("td", "mono", d.usage || "—"), el("td", "mono", d.lease || "—"));
    const route = document.createElement("td");
    const sw = document.createElement("input");
    sw.className = "sw";
    sw.type = "checkbox";
    sw.checked = !!d.vpn;
    const label = el("span", "route-label", d.vpn ? "Mullvad" : "Direct");
    sw.setAttribute("aria-label", (d.vpn ? "Mullvad" : "Direct") + " for " + d.name);
    sw.addEventListener("change", async () => {
      busy = true;
      label.textContent = sw.checked ? "Mullvad" : "Direct";
      try {
        await api("/api/device/vpn", { ip: d.ip, enabled: sw.checked });
        flash(sw.checked ? d.name + " goes through Mullvad" : d.name + " uses your normal connection");
        await refresh();
      } catch (err) {
        sw.checked = !sw.checked;
        label.textContent = sw.checked ? "Mullvad" : "Direct";
        flash(err.message);
      } finally {
        busy = false;
      }
    });
    route.append(sw, label);
    const status = document.createElement("td");
    const st = el("span", "st");
    st.append(el("i", "dot " + dotClass(d)), document.createTextNode(statusLabel(d)));
    status.append(st);
    const actions = el("div", "row-actions");
    if (d.source === "wifi") {
      const b = el("button", d.blocked ? "btn mini" : "btn o mini", d.blocked ? "Unblock" : "Block");
      b.type = "button";
      b.addEventListener("click", async () => {
        busy = true;
        try {
          await api("/api/device/block", { mac: d.mac, blocked: !d.blocked });
          flash(d.blocked ? "Unblocked " + d.mac : "Blocked " + d.mac);
          await refresh();
        } catch (err) {
          flash(err.message);
        } finally {
          busy = false;
        }
      });
      actions.append(b);
    }
    if (d.reserved) {
      const b = el("button", "btn o mini", "Forget");
      b.type = "button";
      b.addEventListener("click", async () => {
        busy = true;
        try {
          await api("/api/reservation/delete", { mac: d.mac });
          flash("Forgot " + d.mac);
          await refresh();
        } catch (err) {
          flash(err.message);
        } finally {
          busy = false;
        }
      });
      actions.append(b);
    }
    const action = document.createElement("td");
    action.className = "act";
    if (actions.childNodes.length) action.append(actions);
    tr.append(route, status, action);
    body.append(tr);
  }
}

function linkCell(source) {
  const td = document.createElement("td");
  const wifi = source === "wifi";
  const wrap = el("span", "link");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", wifi ? "#i-wifi" : "#i-eth");
  svg.append(use);
  wrap.append(svg, document.createTextNode(wifi ? "Wi-Fi" : "Ethernet"));
  td.append(wrap);
  return td;
}

function setText(id, value) {
  const n = $(id);
  const next = value || "—";
  if (n.textContent !== next) n.textContent = next;
}

function render() {
  const live = $("live");
  live.querySelector("i").className = data.mullvad.connected ? "" : "dot r";
  live.querySelector("span").textContent = data.mullvad.connected ? "Protected" : "Direct";
  const online = (data.devices || []).filter((d) => d.online);
  const via = online.filter((d) => d.vpn).length;
  setText("stat-online", String(data.online));
  setText("stat-mullvad", String(via));
  setText("stat-direct", String(online.length - via));
  const pct = data.pool_size ? Math.round((data.leases_used / data.pool_size) * 100) : 0;
  setText("pool-label", data.dhcp_enabled ? "Address pool · " + pct + "% used" : "Address pool · off");
  $("pool-bar").style.width = (data.dhcp_enabled ? pct : 0) + "%";
  $("dhcp-sw").checked = !!data.dhcp_enabled;
  const w = data.pools.wifi, l = data.pools.lan;
  setText("wifi-range", w.start + " – " + w.end);
  setText("wifi-gw", w.gateway);
  setText("lan-range", l.start + " – " + l.end);
  setText("lan-gw", l.gateway);
  setText("dns", data.dns.tunnel);
  setText("lease", w.lease);
  setText("vpn-state", data.mullvad.connected ? "Connected" : "Disconnected");
  setText("vpn-relay", data.mullvad.relay);
  setText("vpn-loc", data.mullvad.location);
  setText("vpn-ip", data.mullvad.exit_ip);
  setText("ov-relay", data.mullvad.connected ? data.mullvad.relay : "Not connected");
  setText("ov-loc", data.mullvad.location);
  setText("ov-exit", data.mullvad.exit_ip);
  setText("ov-leases", data.leases_used + " of " + data.pool_size);
  setText("vpn-pin", data.mullvad.pinned || "Any city");
  const gsw = $("guest-sw");
  const gssid = $("guest-ssid");
  if (gsw && document.activeElement !== gsw) gsw.checked = !!(data.guest && data.guest.enabled);
  if (gssid && document.activeElement !== gssid && data.guest) gssid.value = data.guest.ssid || "";
  $("vpn-btn").textContent = data.mullvad.connected ? "Disconnect" : "Connect";
  const ssid = $("ssid");
  if (document.activeElement !== ssid) ssid.value = data.wifi.ssid;
  $("ap-copy").textContent = data.wifi.ssid + " · channel " + data.wifi.channel + " · " + data.wifi.country + ". A new password reconnects everyone.";
  $("foot").textContent = "YumPi · " + data.model + " · up " + data.uptime;
  if (!busy) renderDevices();
}

async function refresh() {
  data = await api("/api/status");
  render();
}

function fillCities() {
  const code = $("country").value;
  const city = $("city");
  city.replaceChildren();
  city.append(new Option("Best in country", ""));
  const found = relays.find((c) => c.code === code);
  if (!found) return;
  for (const c of found.cities || []) city.append(new Option(c.name, c.code));
}

async function loadRelays() {
  try {
    const payload = await api("/api/relays");
    relays = payload.countries || [];
    const country = $("country");
    country.replaceChildren();
    for (const c of relays) country.append(new Option(c.name, c.code));
    const pin = ((data && data.mullvad && data.mullvad.pinned) || "").trim().split(/\s+/);
    const pinned = relays.find((c) => c.code === pin[0]);
    const us = relays.find((c) => c.code === "us");
    if (pinned) country.value = pinned.code;
    else if (us) country.value = "us";
    fillCities();
    if (pinned && pin[1]) $("city").value = pin[1];
  } catch (err) {
    $("vpn-err").textContent = err.message;
  }
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("login-err").textContent = "";
  try {
    await api("/api/login", { password: new FormData(ev.target).get("password") });
    showApp();
    await refresh();
    loadRelays();
    timer = setInterval(() => { refresh().catch(() => {}); }, 5000);
  } catch (err) {
    $("login-err").textContent = err.message;
  }
});

$("signout").addEventListener("click", async () => {
  try { await api("/api/logout", {}); } catch { /* already signed out */ }
  showLogin();
});

$("q").addEventListener("input", () => { if (data) renderDevices(); });

const pages = ["overview", "devices", "dhcp", "settings"];

function showPage() {
  const raw = location.hash.replace("#", "");
  const name = pages.includes(raw) ? raw : "overview";
  for (const p of pages) {
    const node = $("page-" + p);
    if (node) node.hidden = p !== name;
  }
  document.querySelectorAll("[data-nav]").forEach((n) => {
    n.classList.toggle("on", n.dataset.nav === name);
  });
}

window.addEventListener("hashchange", showPage);
showPage();

$("dhcp-sw").addEventListener("change", async () => {
  const on = $("dhcp-sw").checked;
  try {
    await api("/api/dhcp", { enabled: on });
    flash(on ? "DHCP is on" : "DHCP is off");
    await refresh();
  } catch (err) {
    $("dhcp-sw").checked = !on;
    flash(err.message);
  }
});

$("reserve").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("reserve-err").textContent = "";
  const f = new FormData(ev.target);
  try {
    await api("/api/reservation", { mac: f.get("mac"), ip: f.get("ip"), name: f.get("name") });
    ev.target.reset();
    flash("Reservation saved");
    await refresh();
  } catch (err) {
    $("reserve-err").textContent = err.message;
  }
});

async function useLocation() {
  const country = $("country").value;
  const city = $("city").value;
  if (!country) throw new Error("Choose a country.");
  const location = city ? country + " " + city : country;
  await api("/api/mullvad", { action: "location", location });
  return location;
}

$("vpn-btn").addEventListener("click", async () => {
  $("vpn-err").textContent = "";
  try {
    if (data && data.mullvad.connected) {
      await api("/api/mullvad", { action: "disconnect" });
      flash("Disconnecting");
    } else if ($("country").value) {
      await useLocation();
      flash("Connecting to the location you chose");
    } else {
      await api("/api/mullvad", { action: "connect" });
      flash("Connecting");
    }
    setTimeout(() => refresh().catch(() => {}), 1200);
  } catch (err) {
    $("vpn-err").textContent = err.message;
  }
});

$("country").addEventListener("change", fillCities);

$("loc-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("vpn-err").textContent = "";
  try {
    const location = await useLocation();
    flash("Connecting to " + location);
    setTimeout(() => refresh().catch(() => {}), 1500);
  } catch (err) {
    $("vpn-err").textContent = err.message;
  }
});

$("unpin-btn").addEventListener("click", async () => {
  $("vpn-err").textContent = "";
  try {
    await api("/api/mullvad", { action: "unpin" });
    flash("Using any city");
    setTimeout(() => refresh().catch(() => {}), 1200);
  } catch (err) {
    $("vpn-err").textContent = err.message;
  }
});

$("guest-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("guest-err").textContent = "";
  const f = new FormData(ev.target);
  try {
    await api("/api/guest", { enabled: $("guest-sw").checked, ssid: f.get("ssid"), passphrase: f.get("passphrase") });
    ev.target.querySelector("[name=passphrase]").value = "";
    flash($("guest-sw").checked ? "Guest Wi-Fi is on" : "Guest Wi-Fi is off");
    await refresh();
  } catch (err) {
    $("guest-err").textContent = err.message;
  }
});

$("wifi-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("wifi-err").textContent = "";
  const f = new FormData(ev.target);
  try {
    await api("/api/wifi", { ssid: f.get("ssid"), passphrase: f.get("passphrase") });
    ev.target.querySelector("[name=passphrase]").value = "";
    flash("Wi-Fi updated");
    await refresh();
  } catch (err) {
    $("wifi-err").textContent = err.message;
  }
});

refresh().then(() => {
  showApp();
  loadRelays();
  timer = setInterval(() => { refresh().catch(() => {}); }, 5000);
}).catch((err) => {
  if (err.message === "Sign in.") return;
  $("boot").textContent = err.message;
});
