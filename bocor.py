# lang: Python, file: bocor.py, target: Python 3.8+
# deps: pip install rich requests kodenik
# run standalone: python bocor.py
# import: from bocor import run_bocor

import hashlib
import os
import time
import asyncio
import requests

try:
    from kodenik import lookup_nik as _kodenik_lookup
    KODENIK_OK = True
except ImportError:
    KODENIK_OK = False
    _kodenik_lookup = None

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import box
    RICH_OK = True
    console = Console()
except ImportError:
    RICH_OK = False
    console = None

# ================================================================== #
#  ASCII / COLORS
# ================================================================== #
ASCII_ART = """
███╗   ███╗██████╗ ██╗  ██╗ ██╗ ██╗  ███╗  ███╗       ██╗██████╗ 
████╗ ████║██╔══██╗██║  ██║ ██║ ██║ ██╔██╗ ██╔██╗      ██║██╔══██╗
██╔████╔██║██████╔╝███████║ ███████║██╔╝██╗██╔╝██╗     ██║██║  ██║
██║╚██╔╝██║██╔══██╗╚════██║ ╚════██║██████╔╝██████╔╝   ██║██║  ██║
██║ ╚═╝ ██║██║  ██║      ██║      ██║╚═██╔═╝╚═██╔═╝    ██║██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝      ╚═╝  ╚═╝    ╚═╝     ╚═╝╚═════╝ 
"""
COLORS = ["red", "yellow", "green", "cyan", "blue", "magenta"]

UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"

# ================================================================== #
#  HIBP META CACHE
# ================================================================== #
_hibp_cache: dict = {}

def load_hibp_metadata():
    if _hibp_cache:
        return
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "bocor-py/2.0"}, timeout=10)
        if r.status_code == 200:
            for b in r.json():
                _hibp_cache[b["Name"].lower()] = b
    except Exception:
        pass

def get_hibp_meta(name: str) -> dict:
    return _hibp_cache.get((name or "").lower(), {})

# ================================================================== #
#  SEVERITY
# ================================================================== #
SENSITIVE_FIELDS = {
    "passwords", "password", "credit cards", "bank account numbers",
    "phone numbers", "physical addresses", "dates of birth",
    "government id numbers", "nik", "social security numbers",
}

def severity(data_classes):
    dc = {d.lower() for d in (data_classes or [])}
    if dc & SENSITIVE_FIELDS:
        return "TINGGI"
    if "email addresses" in dc and len(dc) > 2:
        return "SEDANG"
    return "RENDAH"

# ================================================================== #
#  SOURCES
# ================================================================== #
def xon_check_email(email):
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            raw = r.json().get("breaches", [])
            return [b[0] if isinstance(b, list) else b for b in raw]
        if r.status_code == 404:
            return []
    except Exception:
        pass
    return None

def leaklookup_check(query, search_type, key):
    if not key:
        return None
    try:
        r = requests.post(
            "https://leak-lookup.com/api/search",
            data={"key": key, "type": search_type, "query": query},
            timeout=15)
        if r.status_code == 200:
            data = r.json()
            if str(data.get("error")).lower() == "false":
                msg = data.get("message", {})
                return list(msg.keys()) if isinstance(msg, dict) else []
            return []
    except Exception:
        pass
    return None

def leakcheck_check(query):
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={query}",
            headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return [s.get("name", "unknown") for s in data.get("sources", [])]
            return []
    except Exception:
        pass
    return None

def hibp_password_check(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, c = line.split(":")
                if h == suffix:
                    return int(c)
        return 0
    except Exception:
        return -1

def abstract_phone_check(phone, api_key):
    if not api_key:
        return {}
    try:
        r = requests.get(
            "https://phoneintelligence.abstractapi.com/v1/",
            params={"api_key": api_key, "phone": phone},
            timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def format_phone_id(phone):
    phone = phone.strip().replace(" ", "").replace("-", "")
    if phone.startswith("0"):
        phone = "62" + phone[1:]
    elif phone.startswith("+"):
        phone = phone[1:]
    return phone

# ================================================================== #
#  BPJS
# ================================================================== #
def check_bpjs_pasti(nik, tgl_iso):
    res = {"status": "tidak_ada", "nama": None}
    try:
        s = requests.Session()
        s.headers.update({
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://pasti.bpjs-kesehatan.go.id",
            "Referer": "https://pasti.bpjs-kesehatan.go.id/cek",
        })
        s.get("https://pasti.bpjs-kesehatan.go.id/cek", timeout=10)
        r = s.post(
            "https://pasti.bpjs-kesehatan.go.id/api/cek-peserta",
            json={"nik": nik, "tanggalLahir": tgl_iso}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            nama = (data.get("nama") or data.get("namaPeserta")
                    or data.get("data", {}).get("nama")
                    or data.get("peserta", {}).get("nama"))
            status_raw = (data.get("status") or data.get("statusKepesertaan")
                          or data.get("data", {}).get("status")
                          or data.get("peserta", {}).get("status"))
            if nama:
                res["nama"] = str(nama)
            if status_raw:
                st = str(status_raw).lower()
                if "aktif" in st and "non" not in st and "tidak" not in st:
                    res["status"] = "aktif"
                elif "non" in st or "tidak" in st:
                    res["status"] = "nonaktif"
                else:
                    res["status"] = st
    except Exception:
        pass
    return res

def check_bpjs_pasti_multi(nik, tgl, bulan, tahun):
    for th in (tahun, tahun + 1, tahun - 1):
        res = check_bpjs_pasti(nik, f"{th}-{bulan}-{tgl}")
        if res["status"] in ("aktif", "nonaktif"):
            res["tahun_ketemu"] = th
            return res
        time.sleep(0.8)
    return {"status": "tidak_ada", "nama": None, "tahun_ketemu": None}

def parse_nik(nik):
    nik = nik.strip()
    if len(nik) != 16 or not nik.isdigit():
        return None
    tgl = int(nik[6:8]); bulan = nik[8:10]; tahun = nik[10:12]; urut = nik[12:16]
    jk = "Perempuan" if tgl > 40 else "Laki-laki"
    tgl_l = tgl - 40 if tgl > 40 else tgl
    bmap = {"01":"Januari","02":"Februari","03":"Maret","04":"April","05":"Mei","06":"Juni",
            "07":"Juli","08":"Agustus","09":"September","10":"Oktober","11":"November","12":"Desember"}
    th_int = int(tahun)
    th_full = 2000 + th_int if th_int <= 24 else 1900 + th_int
    wilayah = None
    if KODENIK_OK:
        try:
            wilayah = _kodenik_lookup(nik)
        except Exception:
            wilayah = None
    return {
        "nik": nik, "tgl": f"{tgl_l:02d}", "bulan": bulan,
        "bulan_nama": bmap.get(bulan, bulan), "tahun": th_full,
        "jk": jk, "urut": urut, "wilayah": wilayah,
    }

# ================================================================== #
#  CLI HELPERS
# ================================================================== #
def print_banner():
    if not RICH_OK:
        print(ASCII_ART)
        return
    console.clear()
    lines = ASCII_ART.strip().split("\n")
    art = Text()
    for i, line in enumerate(lines):
        art.append(line + "\n", style=f"bold {COLORS[i % len(COLORS)]}")
    console.print(Align.center(art))
    console.print(Align.center(Text("[ MR414N-ID | Data Breach Checker | v2.0 ]", style="bold cyan")))
    console.print()

def merge_breach_names(*lists):
    seen = set(); merged = []
    for lst in lists:
        for name in (lst or []):
            k = name.lower()
            if k not in seen:
                seen.add(k); merged.append(name)
    return merged

def display_email_results(email, breach_names):
    if not RICH_OK:
        if not breach_names:
            print(f"✅ {email} — tidak ditemukan breach")
            return
        print(f"⚠️ {email} — {len(breach_names)} breach")
        for n in breach_names:
            print(f"  - {n}")
        return
    console.print()
    if not breach_names:
        console.print(Align.center(Panel(
            Align.center(Text("✅  Tidak ditemukan di breach manapun", style="bold green")),
            border_style="green", padding=(1, 4), width=60)))
        return
    summary = Text(justify="center")
    summary.append(f"⚠️  {email}\n", style="bold white")
    summary.append("ditemukan di ", style="white")
    summary.append(f"{len(breach_names)} breach", style="bold red")
    console.print(Align.center(Panel(summary, border_style="red", padding=(1, 4), width=72)))
    table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold cyan",
                  show_lines=True, expand=True)
    table.add_column("Breach", style="bold white", min_width=18)
    table.add_column("Tahun", justify="center", min_width=6)
    table.add_column("Akun", justify="right", min_width=10)
    table.add_column("Data", min_width=28)
    table.add_column("Severity", justify="center", min_width=10)
    for name in breach_names:
        meta = get_hibp_meta(name)
        year = (meta.get("BreachDate") or "")[:4] or "—"
        pc = meta.get("PwnCount", 0)
        pwn = f"{pc/1_000_000:.1f}M" if pc >= 1_000_000 else (f"{pc/1_000:.0f}K" if pc >= 1_000 else str(pc))
        dc = meta.get("DataClasses", [])
        fields = ", ".join(dc[:5]) + (f" +{len(dc)-5}" if len(dc) > 5 else "") if dc else "tidak diketahui"
        sev = severity(dc)
        style = {"TINGGI":"bold red","SEDANG":"bold yellow","RENDAH":"bold green"}[sev]
        table.add_row(name, year, pwn, fields, Text(sev, style=style))
    console.print(table)

# ================================================================== #
#  CLI MODE
# ================================================================== #
def cli_check_email(email, cfg):
    print_banner() if not RICH_OK else None
    xon = xon_check_email(email)
    ll = leaklookup_check(email, "email_address", cfg.get("leaklookup"))
    lc = leakcheck_check(email)
    merged = merge_breach_names(xon, ll, lc)
    display_email_results(email, merged)

def cli_check_username(username, cfg):
    xon = xon_check_email(username)
    ll = leaklookup_check(username, "username", cfg.get("leaklookup"))
    lc = leakcheck_check(username)
    merged = merge_breach_names(xon, ll, lc)
    if RICH_OK:
        if not merged:
            console.print(Panel(Text(f"✅  Username '{username}' bersih", style="bold green"),
                                border_style="green", padding=(1,4), width=60))
        else:
            console.print(Panel(Text(f"⚠️  '{username}' di {len(merged)} breach: {', '.join(merged)}",
                                     style="bold red"), border_style="red", padding=(1,4), width=72))
    else:
        print(f"{username}: {len(merged)} breach")

def cli_check_phone(phone, cfg):
    normalized = format_phone_id(phone)
    data = abstract_phone_check(normalized, cfg.get("abstractapi"))
    if not data:
        print("⚠️ AbstractAPI key kosong atau gagal.")
        return
    if RICH_OK:
        t = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold cyan", expand=True)
        t.add_column("Field", style="bold white", min_width=22)
        t.add_column("Info", min_width=36)
        t.add_row("Nomor", f"+{normalized}")
        t.add_row("Valid", "✅" if data.get("valid") else "❌")
        carrier = data.get("carrier") or {}
        country = data.get("country") or {}
        t.add_row("Negara", country.get("name", "—") if isinstance(country, dict) else str(country))
        t.add_row("Operator", carrier.get("name", "—") if isinstance(carrier, dict) else str(carrier))
        t.add_row("Tipe", data.get("type", "—"))
        br = data.get("phone_breaches") or {}
        total = br.get("total_breaches", 0) if isinstance(br, dict) else 0
        t.add_row("Total Breach", Text(str(total), style="bold red") if total else "✅ 0")
        if total:
            t.add_row("Pertama", br.get("date_first_breached", "—"))
            t.add_row("Terakhir", br.get("date_last_breached", "—"))
        console.print(t)
    else:
        print(f"+{normalized}: valid={data.get('valid')}")

def cli_check_password(password):
    cnt = hibp_password_check(password)
    if RICH_OK:
        if cnt == -1:
            console.print(Panel(Text("⚠️  Gagal ke HIBP", style="bold red"), border_style="red"))
        elif cnt == 0:
            console.print(Panel(Text("✅  Password bersih", style="bold green"), border_style="green"))
        else:
            console.print(Panel(Text(f"⚠️  Muncul {cnt:,}x di breach", style="bold red"),
                                border_style="red"))
    else:
        print(f"count: {cnt}")

def cli_check_nik(nik):
    p = parse_nik(nik)
    if not p:
        print("❌ NIK tidak valid.")
        return
    bpjs = check_bpjs_pasti_multi(p["nik"], p["tgl"], p["bulan"], p["tahun"])
    if RICH_OK:
        t = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold cyan", expand=True)
        t.add_column("Field", style="bold white", min_width=22)
        t.add_column("Info", min_width=36)
        t.add_row("NIK", p["nik"])
        if p["wilayah"]:
            t.add_row("Provinsi", p["wilayah"].get("nama_provinsi", "—"))
            t.add_row("Kab/Kota", p["wilayah"].get("nama_kabkota", "—"))
            t.add_row("Kecamatan", p["wilayah"].get("nama_kecamatan", "—"))
        t.add_row("Tgl Lahir", f"{p['tgl']} {p['bulan_nama']} {p['tahun']}")
        t.add_row("JK", p["jk"])
        t.add_row("No. Urut", p["urut"])
        if bpjs["status"] in ("aktif", "nonaktif"):
            t.add_row("BPJS", Text(bpjs["status"].capitalize(),
                                   style="bold green" if bpjs["status"]=="aktif" else "bold red"))
            if bpjs.get("nama"):
                t.add_row("Nama", bpjs["nama"])
        else:
            t.add_row("BPJS", Text("tidak aktif", style="dim yellow"))
        console.print(t)
    else:
        print(f"NIK {p['nik']} | {p['jk']} | {p['tgl']}/{p['bulan']}/{p['tahun']}")

def show_menu():
    m = Text(justify="center")
    m.append("  [1] ", style="bold cyan"); m.append("Email      ", style="white")
    m.append("[2] ", style="bold cyan");   m.append("Username   ", style="white")
    m.append("[3] ", style="bold cyan");   m.append("No. HP     ", style="white")
    m.append("[4] ", style="bold cyan");   m.append("NIK        ", style="white")
    m.append("[5] ", style="bold cyan");   m.append("Password   ", style="white")
    m.append("[0] ", style="bold red");    m.append("Keluar", style="white")
    console.print(Align.center(Panel(m, border_style="bright_cyan", padding=(0, 2), width=72)))

def main():
    if not RICH_OK:
        print("[!] pip install rich"); return
    cfg = {
        "leaklookup": os.getenv("LEAKLOOKUP_KEY", ""),
        "abstractapi": os.getenv("ABSTRACTAPI_KEY", ""),
    }
    print_banner()
    console.print(Align.center(Text("⏳ Memuat HIBP...", style="dim")))
    load_hibp_metadata()
    console.print(Align.center(Text(f"✅ {len(_hibp_cache)} breach dimuat\n", style="dim green")))

    while True:
        show_menu()
        p = Prompt.ask("[bold cyan]Pilih[/bold cyan]", choices=["0","1","2","3","4","5"], default="1")
        if p == "0":
            break
        try:
            if p == "1":
                v = Prompt.ask("Email").strip()
                if v: cli_check_email(v, cfg)
            elif p == "2":
                v = Prompt.ask("Username").strip()
                if v: cli_check_username(v, cfg)
            elif p == "3":
                v = Prompt.ask("No. HP (08xx)").strip()
                if v: cli_check_phone(v, cfg)
            elif p == "4":
                v = Prompt.ask("NIK (16 digit)").strip()
                if v: cli_check_nik(v)
            elif p == "5":
                v = Prompt.ask("Password", password=True).strip()
                if v: cli_check_password(v)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        console.print()
        input("[dim]Enter untuk lanjut...[/dim]")
        print_banner()

# ================================================================== #
#  TELEGRAM FORMATTER
# ================================================================== #
def _esc(s):
    if s is None:
        return "—"
    s = str(s)
    for ch in ["_", "*", "`", "["]:
        s = s.replace(ch, "\\" + ch)
    return s

def _fmt_breach_list(term, names):
    if not names:
        return f"✅ *Tidak ditemukan breach* untuk `{_esc(term)}`"
    load_hibp_metadata()
    out = [f"⚠️ *{_esc(term)}* — ditemukan di *{len(names)} breach*:\n"]
    for name in names:
        meta = get_hibp_meta(name)
        year = (meta.get("BreachDate") or "")[:4] or "—"
        dc = meta.get("DataClasses", [])
        dc_str = ", ".join(dc[:4]) + (f" +{len(dc)-4}" if len(dc) > 4 else "") if dc else "tidak diketahui"
        sev = severity(dc)
        icon = {"TINGGI":"🔴","SEDANG":"🟡","RENDAH":"🟢"}[sev]
        out.append(f"{icon} *{_esc(name)}* ({year})\n   `{_esc(dc_str)}`")
    out.append("\n💡 Ganti password akun terdampak, aktifkan 2FA.")
    return "\n".join(out)

def _fmt_phone(phone, data, has_key):
    if not data:
        if not has_key:
            return "⚠️ `ABSTRACTAPI_KEY` belum diisi di `say.py`.\nIsi dulu untuk aktifkan cek breach nomor HP."
        return "⚠️ Gagal terhubung ke AbstractAPI."
    carrier = data.get("carrier") or {}
    country = data.get("country") or {}
    breaches = data.get("phone_breaches") or {}
    risk = data.get("phone_risk") or {}
    out = [f"📱 *Phone Lookup* `+{_esc(phone)}`\n"]
    out.append(f"Negara: {_esc(country.get('name') if isinstance(country, dict) else country)}")
    out.append(f"Operator: {_esc(carrier.get('name') if isinstance(carrier, dict) else carrier)}")
    out.append(f"Tipe: {_esc(data.get('type'))}")
    out.append(f"Valid: {'✅' if data.get('valid') else '❌'}")
    total = breaches.get("total_breaches", 0) if isinstance(breaches, dict) else 0
    if total:
        out.append(f"\n🔴 *Total breach:* {total}")
        out.append(f"Pertama: {_esc(breaches.get('date_first_breached'))}")
        out.append(f"Terakhir: {_esc(breaches.get('date_last_breached'))}")
        doms = breaches.get("breached_domains", [])
        if doms:
            d_str = ", ".join((bd.get("domain", "?") if isinstance(bd, dict) else str(bd)) for bd in doms[:8])
            out.append(f"Domain: {_esc(d_str)}")
    else:
        out.append("\n✅ Tidak ada breach")
    if isinstance(risk, dict) and risk:
        if risk.get("is_abuse_detected"): out.append("⚠️ Spam/abuse terdeteksi")
        if risk.get("is_disposable"): out.append("⚠️ Nomor disposable")
    return "\n".join(out)

def _fmt_password(count):
    if count == -1:
        return "⚠️ Gagal terhubung ke HIBP."
    if count == 0:
        return "✅ Password *tidak ditemukan* di breach manapun."
    return (f"🔴 Password muncul *{count:,}x* di breach!\n"
            f"Segera ganti password ini di semua akun.\n\n"
            f"_Hanya 5 char pertama SHA1 yang dikirim — password tidak pernah utuh_")

def _fmt_nik(p, bpjs):
    out = [f"🪪 *NIK Lookup*\n\n`{p['nik']}`\n"]
    if p.get("wilayah"):
        out.append(f"Provinsi: *{_esc(p['wilayah'].get('nama_provinsi','—'))}*")
        out.append(f"Kab/Kota: {_esc(p['wilayah'].get('nama_kabkota','—'))}")
        out.append(f"Kecamatan: {_esc(p['wilayah'].get('nama_kecamatan','—'))}")
    elif not KODENIK_OK:
        out.append("_kodenik tidak terinstal — wilayah tidak ditampilkan_")
    out.append(f"Tgl Lahir: *{p['tgl']} {p['bulan_nama']} {p['tahun']}*")
    out.append(f"JK: {p['jk']}")
    out.append(f"No. Urut: {p['urut']}")
    if bpjs["status"] in ("aktif", "nonaktif"):
        icon = "✅" if bpjs["status"] == "aktif" else "🔴"
        out.append(f"\n{icon} *BPJS {bpjs['status'].capitalize()}*")
        if bpjs.get("nama"):
            out.append(f"Nama: *{_esc(bpjs['nama'])}*")
    else:
        out.append("\n🟡 BPJS: tidak aktif / tidak ditemukan")
    out.append("\n_⚠️ Bukan verifikasi Dukcapil — hanya parse struktur NIK + BPJS._")
    return "\n".join(out)

# ================================================================== #
#  TELEGRAM ENTRYPOINT
# ================================================================== #
def run_bocor(uid, query, kind, bot_token, cfg=None):
    from telegram import Bot
    cfg = cfg or {}

    async def _run():
        bot = Bot(token=bot_token)
        label = {"email":"Email","username":"Username","phone":"Nomor HP",
                 "nik":"NIK","password":"Password"}.get(kind, kind)
        try:
            await bot.send_message(chat_id=uid,
                text=f"⏳ Leak DB — {label}: `{query}`", parse_mode="Markdown")
        except Exception:
            pass

        text_out = ""
        try:
            if kind == "email":
                xon = xon_check_email(query)
                ll = leaklookup_check(query, "email_address", cfg.get("leaklookup"))
                lc = leakcheck_check(query)
                text_out = _fmt_breach_list(query, merge_breach_names(xon, ll, lc))
            elif kind == "username":
                xon = xon_check_email(query)
                ll = leaklookup_check(query, "username", cfg.get("leaklookup"))
                lc = leakcheck_check(query)
                text_out = _fmt_breach_list(query, merge_breach_names(xon, ll, lc))
            elif kind == "phone":
                phone = format_phone_id(query)
                data = abstract_phone_check(phone, cfg.get("abstractapi"))
                text_out = _fmt_phone(phone, data, bool(cfg.get("abstractapi")))
            elif kind == "nik":
                p = parse_nik(query)
                if not p:
                    text_out = "❌ NIK tidak valid. Harus 16 digit angka."
                else:
                    bpjs = check_bpjs_pasti_multi(p["nik"], p["tgl"], p["bulan"], p["tahun"])
                    text_out = _fmt_nik(p, bpjs)
            elif kind == "password":
                text_out = _fmt_password(hibp_password_check(query))
            else:
                text_out = "❌ Jenis tidak dikenal."
        except Exception as e:
            text_out = f"❌ Error: `{e}`"

        if len(text_out) > 4000:
            for i in range(0, len(text_out), 4000):
                chunk = text_out[i:i+4000]
                try:
                    await bot.send_message(chat_id=uid, text=chunk, parse_mode="Markdown",
                                           disable_web_page_preview=True)
                except Exception:
                    await bot.send_message(chat_id=uid, text=chunk, disable_web_page_preview=True)
        else:
            try:
                await bot.send_message(chat_id=uid, text=text_out, parse_mode="Markdown",
                                       disable_web_page_preview=True)
            except Exception:
                await bot.send_message(chat_id=uid, text=text_out, disable_web_page_preview=True)

    asyncio.run(_run())

if __name__ == "__main__":
    main()
