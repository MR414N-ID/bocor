# lang: Python, file: bocor.py, target: Python 3.8+
# deps: pip install rich requests kodenik
# run: python bocor.py

import hashlib
import os
import time
import random
import subprocess
import requests
from kodenik import lookup_nik as _kodenik_lookup
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()

# ── load .env manual ────────────────────────────────────────────────────────
def _load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env()

LEAKLOOKUP_KEY   = os.getenv("LEAKLOOKUP_KEY", "")
ABSTRACTAPI_KEY  = os.getenv("ABSTRACTAPI_KEY", "")

ASCII_ART = """
███╗   ███╗██████╗ ██╗  ██╗ ██╗ ██╗  ███╗  ███╗       ██╗██████╗ 
████╗ ████║██╔══██╗██║  ██║ ██║ ██║ ██╔██╗ ██╔██╗      ██║██╔══██╗
██╔████╔██║██████╔╝███████║ ███████║██╔╝██╗██╔╝██╗     ██║██║  ██║
██║╚██╔╝██║██╔══██╗╚════██║ ╚════██║██████╔╝██████╔╝   ██║██║  ██║
██║ ╚═╝ ██║██║  ██║      ██║      ██║╚═██╔═╝╚═██╔═╝    ██║██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝      ╚═╝  ╚═╝    ╚═╝     ╚═╝╚═════╝ 
"""

COLORS = ["red", "yellow", "green", "cyan", "blue", "magenta"]

# ── proxy pool ───────────────────────────────────────────────────────────────
_PROXY_POOL = []

def _load_proxies_from_file(filename):
    global _PROXY_POOL
    try:
        with open(filename) as f:
            _PROXY_POOL = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return True
    except FileNotFoundError:
        return False

def _random_proxy():
    if not _PROXY_POOL:
        return None
    return random.choice(_PROXY_POOL)

def setup_proxy():
    """Menu inisialisasi proxy di awal"""
    console.print(Panel(
        Text("Pilih Mode Koneksi:", style="bold cyan"),
        border_style="cyan", padding=(1, 2), width=50
    ))
    console.print("  [1] Otomatis (Scrape via proxy_id.py)")
    console.print("  [2] Dari file .txt (manual)")
    console.print("  [3] Tanpa Proxy\n")
    
    pilihan = Prompt.ask("[bold white]Pilih mode (1/2/3)[/bold white]", choices=["1", "2", "3"], default="3")
    
    if pilihan == "1":
        console.print("\n[dim]Menjalankan proxy_id.py...[/dim]")
        try:
            subprocess.run(["python", "proxy_id.py"])
        except Exception as e:
            console.print(f"[red]Gagal menjalankan: {e}[/red]")
        
        console.print("\n[dim]Mencari file proxy yang dihasilkan...[/dim]")
        # Cari file proxies*.txt terbaru
        files = [f for f in os.listdir('.') if f.startswith('proxies') and f.endswith('.txt')]
        if files:
            files.sort(key=os.path.getmtime, reverse=True)
            latest = files[0]
            if _load_proxies_from_file(latest):
                console.print(f"[green]✅ {len(_PROXY_POOL)} proxy dimuat dari {latest}[/green]")
        else:
            console.print("[yellow]⚠️ Tidak ada file proxies.txt ditemukan.[/yellow]")
            
    elif pilihan == "2":
        fname = Prompt.ask("[bold white]Masukkan nama file proxy[/bold white]", default="proxies.txt")
        if _load_proxies_from_file(fname):
            console.print(f"[green]✅ {len(_PROXY_POOL)} proxy dimuat dari {fname}[/green]")
        else:
            console.print(f"[red]❌ File '{fname}' tidak ditemukan. Lanjut tanpa proxy.[/red]")
            
    else:
        console.print("[dim]Lanjut tanpa proxy.[/dim]")
    
    time.sleep(1)

# ── banner ───────────────────────────────────────────────────────────────────

def print_banner():
    console.clear()
    lines = ASCII_ART.strip().split("\n")
    colored_art = Text()
    for i, line in enumerate(lines):
        colored_art.append(line + "\n", style=f"bold {COLORS[i % len(COLORS)]}")
    console.print(Align.center(colored_art))

    subtitle = Text()
    for i, ch in enumerate("[ MR414N-ID | Data Breach Checker | v2.0 ]"):
        subtitle.append(ch, style=f"bold {COLORS[i % len(COLORS)]}")
    console.print(Align.center(subtitle))
    console.print()

    info = Text(justify="center")
    info.append("🔍  Cek apakah datamu pernah bocor di internet\n", style="bold white")
    info.append("📧  Email  •  🪪  NIK  •  📱  No. HP  •  👤  Username  •  🔑  Password\n", style="dim white")
    info.append("🔒  Data tidak dikirim utuh — dilindungi hashing lokal", style="dim cyan")
    console.print(Align.center(Panel(info, border_style="bright_cyan", padding=(1, 4), width=72)))
    console.print()

# ── HIBP breach metadata cache ────────────────────────────────────────────────

_hibp_cache: dict = {}

def load_hibp_metadata():
    global _hibp_cache
    if _hibp_cache:
        return
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "bocor-py/2.0"},
            timeout=10,
        )
        if r.status_code == 200:
            for b in r.json():
                _hibp_cache[b["Name"].lower()] = b
    except Exception:
        pass

def get_hibp_meta(breach_name: str) -> dict:
    return _hibp_cache.get(breach_name.lower(), {})

# ── severity helper ───────────────────────────────────────────────────────────

SENSITIVE_FIELDS = {
    "passwords", "password", "credit cards", "bank account numbers",
    "phone numbers", "physical addresses", "dates of birth",
    "government id numbers", "nik", "social security numbers",
}

def severity(data_classes: list) -> tuple:
    dc_lower = {d.lower() for d in data_classes}
    if dc_lower & SENSITIVE_FIELDS:
        return "TINGGI", "bold red"
    if "email addresses" in dc_lower and len(dc_lower) > 2:
        return "SEDANG", "bold yellow"
    return "RENDAH", "bold green"

# ── XposedOrNot ───────────────────────────────────────────────────────────────

def xon_check_email(email: str):
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers={"User-Agent": "bocor-py/2.0"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            raw = data.get("breaches", [])
            return [b[0] if isinstance(b, list) else b for b in raw]
        elif r.status_code == 404:
            return []
    except Exception:
        pass
    return None

def xon_analytics(email: str) -> dict:
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
            headers={"User-Agent": "bocor-py/2.0"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

# ── LeakLookup ────────────────────────────────────────────────────────────────

def leaklookup_check(query: str, search_type: str = "email_address") -> list:
    try:
        r = requests.post(
            "https://leak-lookup.com/api/search",
            data={"key": LEAKLOOKUP_KEY, "type": search_type, "query": query},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("error") == "false" or data.get("error") is False:
                results = data.get("message", {})
                if isinstance(results, dict):
                    return list(results.keys())
                return []
            return []
    except Exception:
        pass
    return None

# ── LeakCheck ─────────────────────────────────────────────────────────────────

def leakcheck_check(query: str) -> list:
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={query}",
            headers={"User-Agent": "bocor-py/2.0"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                sources = data.get("sources", [])
                return [s.get("name", "unknown") for s in sources]
            return []
    except Exception:
        pass
    return None

# ── HIBP password k-anonymity ─────────────────────────────────────────────────

def hibp_password_check(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "bocor-py/2.0"},
            timeout=10,
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
        return 0
    except Exception:
        return -1

# ── AbstractAPI phone breach ──────────────────────────────────────────────────

def abstract_phone_check(phone: str) -> dict:
    try:
        r = requests.get(
            "https://phoneintelligence.abstractapi.com/v1/",
            params={"api_key": ABSTRACTAPI_KEY, "phone": phone},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def format_phone_id(phone: str) -> str:
    phone = phone.strip().replace(" ", "").replace("-", "")
    if phone.startswith("0"):
        phone = "62" + phone[1:]
    elif phone.startswith("+"):
        phone = phone[1:]
    return phone

# ── BPJS PASTI JKN ────────────────────────────────────────────────────────────

def check_bpjs_pasti(nik: str, tgl_lahir_iso: str) -> dict:
    result = {"status": "tidak_ada", "nama": None}
    try:
        s = requests.Session()
        proxy = _random_proxy()
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://pasti.bpjs-kesehatan.go.id",
            "Referer": "https://pasti.bpjs-kesehatan.go.id/cek",
        })
        s.get("https://pasti.bpjs-kesehatan.go.id/cek", timeout=10)

        r = s.post(
            "https://pasti.bpjs-kesehatan.go.id/api/cek-peserta",
            json={"nik": nik, "tanggalLahir": tgl_lahir_iso},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            nama = (
                data.get("nama") or data.get("namaPeserta")
                or data.get("data", {}).get("nama")
                or data.get("peserta", {}).get("nama")
            )
            status_raw = (
                data.get("status") or data.get("statusKepesertaan")
                or data.get("data", {}).get("status")
                or data.get("peserta", {}).get("status")
            )
            if nama:
                result["nama"] = str(nama)
            if status_raw:
                st = str(status_raw).lower()
                if "aktif" in st and "non" not in st and "tidak" not in st:
                    result["status"] = "aktif"
                elif "non" in st or "tidak" in st:
                    result["status"] = "nonaktif"
                else:
                    result["status"] = st
    except Exception:
        pass
    return result

def check_bpjs_pasti_multi(nik: str, tgl: str, bulan: str, tahun: int) -> dict:
    kandidat_tahun = [tahun, tahun + 1, tahun - 1]
    for i, th in enumerate(kandidat_tahun):
        tgl_iso = f"{th}-{bulan}-{tgl}"
        console.print(f"[dim]🔍 BPJS PASTI JKN percobaan {i+1}/3 ({tgl_iso})...[/dim]")
        res = check_bpjs_pasti(nik, tgl_iso)
        if res["status"] in ("aktif", "nonaktif"):
            res["tahun_ketemu"] = th
            return res
        if i < len(kandidat_tahun) - 1:
            time.sleep(1.0)
    return {"status": "tidak_ada", "nama": None, "tahun_ketemu": None}

# ── display email results ─────────────────────────────────────────────────────

def merge_breach_names(xon: list, ll: list, lc: list) -> list:
    seen = set()
    merged = []
    for name in (xon or []) + (ll or []) + (lc or []):
        key = name.lower()
        if key not in seen:
            seen.add(key)
            merged.append(name)
    return merged

def display_email_results(email: str, breach_names: list):
    console.print()
    if not breach_names:
        console.print(Align.center(
            Panel(
                Align.center(Text("✅  Tidak ditemukan di breach manapun", style="bold green")),
                border_style="green", padding=(1, 4), width=60
            )
        ))
        return

    total = len(breach_names)
    summary = Text(justify="center")
    summary.append(f"⚠️  {email}\n", style="bold white")
    summary.append("ditemukan di ", style="white")
    summary.append(f"{total} breach", style="bold red")
    summary.append(" yang diketahui", style="white")
    console.print(Align.center(
        Panel(summary, border_style="red", padding=(1, 4), width=72)
    ))
    console.print()

    table = Table(
        box=box.ROUNDED, border_style="bright_cyan", header_style="bold cyan",
        show_lines=True, expand=True,
    )
    table.add_column("Breach", style="bold white", min_width=18)
    table.add_column("Tahun", justify="center", min_width=6)
    table.add_column("Akun Bocor", justify="right", min_width=12)
    table.add_column("Data Yang Bocor", min_width=28)
    table.add_column("Severity", justify="center", min_width=10)

    for name in breach_names:
        meta = get_hibp_meta(name)
        year = "—"
        if meta.get("BreachDate"):
            year = meta["BreachDate"][:4]
        pwn_count = "—"
        if meta.get("PwnCount"):
            c = meta["PwnCount"]
            if c >= 1_000_000:
                pwn_count = f"{c/1_000_000:.1f}M"
            elif c >= 1_000:
                pwn_count = f"{c/1_000:.0f}K"
            else:
                pwn_count = str(c)

        data_classes = meta.get("DataClasses", [])
        fields_text = Text()
        if data_classes:
            for j, dc in enumerate(data_classes[:5]):
                fields_text.append(dc, style="yellow")
                if j < min(len(data_classes), 5) - 1:
                    fields_text.append(", ", style="dim white")
            if len(data_classes) > 5:
                fields_text.append(f" +{len(data_classes)-5} lagi", style="dim white")
        else:
            fields_text.append("tidak diketahui", style="dim white")

        sev_label, sev_style = severity(data_classes)
        table.add_row(name, year, pwn_count, fields_text, Text(sev_label, style=sev_style))

    console.print(table)
    console.print()
    tips = Text(justify="center")
    tips.append("💡 Tips: ", style="bold cyan")
    tips.append("Ganti password di semua akun yang terdampak. Aktifkan 2FA.", style="white")
    console.print(Align.center(tips))

# ── check email ───────────────────────────────────────────────────────────────

def check_email(email: str):
    console.print(f"\n[dim]🔍 XposedOrNot...[/dim]")
    xon = xon_check_email(email)

    console.print(f"[dim]🔍 LeakLookup...[/dim]")
    ll = leaklookup_check(email, "email_address")

    console.print(f"[dim]🔍 LeakCheck...[/dim]")
    lc = leakcheck_check(email)

    merged = merge_breach_names(xon if xon else [], ll if ll else [], lc if lc else [])

    if xon is None or ll is None or lc is None:
        src_line = Text()
        src_line.append("Sumber: ", style="dim white")
        src_line.append("XON ", style="green" if xon is not None else "red")
        src_line.append("LeakLookup ", style="green" if ll is not None else "red")
        src_line.append("LeakCheck", style="green" if lc is not None else "red")
        console.print(Align.center(src_line))

    display_email_results(email, merged)

# ── check username ────────────────────────────────────────────────────────────

def check_username(username: str):
    console.print(f"\n[dim]🔍 XposedOrNot...[/dim]")
    xon = xon_check_email(username)

    console.print(f"[dim]🔍 LeakLookup...[/dim]")
    ll = leaklookup_check(username, "username")

    console.print(f"[dim]🔍 LeakCheck...[/dim]")
    lc = leakcheck_check(username)

    merged = merge_breach_names(xon if xon else [], ll if ll else [], lc if lc else [])

    console.print()
    if not merged:
        console.print(Align.center(
            Panel(
                Align.center(Text(f"✅  Username '{username}' tidak ditemukan di breach manapun", style="bold green")),
                border_style="green", padding=(1, 4), width=60
            )
        ))
    else:
        total = len(merged)
        console.print(Align.center(
            Panel(
                Align.center(Text(f"⚠️  Username '{username}' ditemukan di {total} breach: {', '.join(merged)}", style="bold red")),
                border_style="red", padding=(1, 4), width=72
            )
        ))

# ── check phone ───────────────────────────────────────────────────────────────

def check_phone(phone: str):
    normalized = format_phone_id(phone)
    console.print(f"\n[dim]🔍 AbstractAPI Phone Intelligence ({normalized})...[/dim]")

    data = abstract_phone_check(normalized)
    console.print()

    if not data:
        console.print(Panel(
            Text("⚠️  Gagal terhubung ke AbstractAPI. Cek koneksi atau API key.", style="bold red"),
            border_style="red", padding=(1, 2)
        ))
        return

    table = Table(box=box.ROUNDED, border_style="bright_cyan",
                  header_style="bold cyan", show_lines=True, expand=True)
    table.add_column("Field", style="bold white", min_width=22)
    table.add_column("Info", min_width=36)

    carrier = data.get("carrier", {})
    country = data.get("country", {})

    table.add_row("Nomor (E.164)", f"+{normalized}")
    table.add_row("Valid", "✅ Ya" if data.get("valid") else "❌ Tidak")
    table.add_row("Negara", country.get("name", "—") if isinstance(country, dict) else str(country))
    table.add_row("Operator", carrier.get("name", "—") if isinstance(carrier, dict) else str(carrier))
    table.add_row("Tipe", data.get("type", "—"))

    breaches = data.get("phone_breaches", {})
    total_breaches = breaches.get("total_breaches", 0) if isinstance(breaches, dict) else 0

    if total_breaches and total_breaches > 0:
        table.add_row("Total Breach", Text(str(total_breaches), style="bold red"))
        table.add_row("Pertama Bocor", breaches.get("date_first_breached", "—"))
        table.add_row("Terakhir Bocor", breaches.get("date_last_breached", "—"))

        breached_domains = breaches.get("breached_domains", [])
        if breached_domains:
            domains_text = Text()
            for i, bd in enumerate(breached_domains[:8]):
                domain = bd.get("domain", "?") if isinstance(bd, dict) else str(bd)
                date   = bd.get("breach_date", "") if isinstance(bd, dict) else ""
                domains_text.append(domain, style="yellow")
                if date:
                    domains_text.append(f" ({date[:4]})", style="dim white")
                if i < len(breached_domains) - 1:
                    domains_text.append(", ")
            if len(breached_domains) > 8:
                domains_text.append(f" +{len(breached_domains)-8} lagi", style="dim white")
            table.add_row("Domain Bocor", domains_text)
    else:
        table.add_row("Breach", Text("✅ Tidak ditemukan", style="bold green"))

    risk = data.get("phone_risk", {})
    if isinstance(risk, dict) and risk:
        table.add_row("Spam/Abuse", "⚠️ Terdeteksi" if risk.get("is_abuse_detected") else "✅ Bersih")
        table.add_row("Nomor Disposable", "⚠️ Ya" if risk.get("is_disposable") else "✅ Tidak")

    console.print(table)

# ── check password ────────────────────────────────────────────────────────────

def check_password(password: str):
    console.print(f"\n[dim]🔍 HIBP Pwned Passwords (k-anonymity)...[/dim]")
    count = hibp_password_check(password)
    console.print()

    if count == -1:
        console.print(Panel(
            Text("⚠️  Gagal terhubung ke HIBP.", style="bold red"),
            border_style="red", padding=(1, 2)
        ))
    elif count == 0:
        console.print(Align.center(
            Panel(
                Align.center(Text("✅  Password tidak ditemukan di breach manapun", style="bold green")),
                border_style="green", padding=(1, 4), width=60
            )
        ))
    else:
        console.print(Align.center(
            Panel(
                Align.center(Text(
                    f"⚠️  Password ini muncul {count:,}x di breach yang diketahui!\n"
                    f"Segera ganti password ini di semua akun.",
                    style="bold red", justify="center"
                )),
                border_style="red", padding=(1, 4), width=72
            )
        ))

    console.print()
    console.print(Align.center(
        Text("🔒  Password tidak pernah dikirim utuh — hanya 5 karakter pertama hash SHA1", style="dim cyan")
    ))

# ── check NIK ─────────────────────────────────────────────────────────────────

def check_nik(nik: str):
    nik = nik.strip()
    console.print()

    if len(nik) != 16 or not nik.isdigit():
        console.print(Panel(
            Text("❌  NIK tidak valid. Harus 16 digit angka.", style="bold red"),
            border_style="red", padding=(1, 2)
        ))
        return

    tgl   = int(nik[6:8])
    bulan = nik[8:10]
    tahun = nik[10:12]
    urut  = nik[12:16]

    jk        = "Perempuan" if tgl > 40 else "Laki-laki"
    tgl_lahir = tgl - 40 if tgl > 40 else tgl

    bulan_map = {
        "01":"Januari","02":"Februari","03":"Maret","04":"April",
        "05":"Mei","06":"Juni","07":"Juli","08":"Agustus",
        "09":"September","10":"Oktober","11":"November","12":"Desember",
    }

    tgl_str    = str(tgl_lahir).zfill(2)
    bulan_str  = bulan_map.get(bulan, bulan)
    tahun_int  = int(tahun)
    tahun_full = 2000 + tahun_int if tahun_int <= 24 else 1900 + tahun_int

    console.print(f"[dim]🔍 Lookup wilayah via kodenik...[/dim]")
    wilayah = None
    try:
        wilayah = _kodenik_lookup(nik)
    except Exception:
        wilayah = None

    table = Table(box=box.ROUNDED, border_style="bright_cyan",
                  header_style="bold cyan", show_lines=True, expand=True)
    table.add_column("Field", style="bold white", min_width=22)
    table.add_column("Info", min_width=36)

    table.add_row("NIK", nik)

    if wilayah:
        table.add_row("Provinsi",       Text(wilayah.get("nama_provinsi", "—"),  style="bold yellow"))
        table.add_row("Kabupaten/Kota", Text(wilayah.get("nama_kabkota", "—"),   style="yellow"))
        table.add_row("Kecamatan",      Text(wilayah.get("nama_kecamatan", "—"), style="yellow"))

    table.add_row("Tanggal Lahir", Text(f"{tgl_str} {bulan_str} {tahun_full}", style="bold white"))
    table.add_row("Jenis Kelamin", Text(jk, style="bold cyan"))
    table.add_row("No. Urut", urut)

    bpjs = check_bpjs_pasti_multi(nik, tgl_str, bulan, tahun_full)

    if bpjs["status"] in ("aktif", "nonaktif"):
        style = "bold green" if bpjs["status"] == "aktif" else "bold red"
        table.add_row("BPJS", Text(bpjs["status"].capitalize(), style=style))
        if bpjs.get("nama"):
            table.add_row("Nama (BPJS)", Text(bpjs["nama"], style="bold white"))
        else:
            table.add_row("Nama (BPJS)", Text("—", style="dim white"))
        if bpjs.get("tahun_ketemu") and bpjs["tahun_ketemu"] != tahun_full:
            table.add_row("Tahun Ditemukan", Text(str(bpjs["tahun_ketemu"]), style="bold cyan"))
    else:
        table.add_row("BPJS", Text("Database BPJS tidak ada atau tidak aktif", style="dim yellow"))

    console.print(table)
    console.print()
    console.print(Align.center(
        Panel(
            Align.center(Text(
                "⚠️  Tidak ada API publik untuk cek breach NIK.\n"
                "Di atas adalah parse struktur NIK + BPJS PASTI JKN — bukan verifikasi Dukcapil.",
                style="dim yellow", justify="center"
            )),
            border_style="yellow", padding=(1, 2), width=72
        )
    ))

# ── menu utama ────────────────────────────────────────────────────────────────

def show_menu():
    menu = Text(justify="center")
    menu.append("  [1]", style="bold cyan"); menu.append(" Cek Email      ", style="white")
    menu.append("[2]", style="bold cyan");   menu.append(" Cek Username   ", style="white")
    menu.append("[3]", style="bold cyan");   menu.append(" Cek No. HP     ", style="white")
    menu.append("[4]", style="bold cyan");   menu.append(" Cek NIK        ", style="white")
    menu.append("[5]", style="bold cyan");   menu.append(" Cek Password   ", style="white")
    menu.append("[0]", style="bold red");    menu.append(" Keluar  ", style="white")
    console.print(Align.center(Panel(menu, border_style="bright_cyan", padding=(0, 2), width=72)))
    console.print()

def main():
    print_banner()
    
    # Panggil menu setup proxy
    setup_proxy()
    
    console.print(Align.center(Text("⏳  Memuat breach database HIBP...", style="dim white")))
    load_hibp_metadata()
    console.print(Align.center(Text(f"✅  {len(_hibp_cache)} breach dimuat\n", style="dim green")))

    while True:
        show_menu()
        pilihan = Prompt.ask(
            "[bold cyan]Pilih[/bold cyan]",
            choices=["0", "1", "2", "3", "4", "5"],
            default="1"
        )

        if pilihan == "0":
            console.print("\n[dim]bye.[/dim]\n")
            break
        elif pilihan == "1":
            email = Prompt.ask("[bold white]Masukkan email[/bold white]").strip()
            if email: check_email(email)
        elif pilihan == "2":
            username = Prompt.ask("[bold white]Masukkan username[/bold white]").strip()
            if username: check_username(username)
        elif pilihan == "3":
            phone = Prompt.ask("[bold white]Masukkan No. HP (contoh: 08123456789)[/bold white]").strip()
            if phone: check_phone(phone)
        elif pilihan == "4":
            nik = Prompt.ask("[bold white]Masukkan NIK (16 digit)[/bold white]").strip()
            if nik: check_nik(nik)
        elif pilihan == "5":
            password = Prompt.ask("[bold white]Masukkan password[/bold white]", password=True).strip()
            if password: check_password(password)

        console.print()
        input("[dim]Tekan Enter untuk lanjut...[/dim]")
        print_banner()
        if _PROXY_POOL:
            console.print(Align.center(Text(f"🌐  {len(_PROXY_POOL)} proxy dimuat\n", style="dim cyan")))
        console.print(Align.center(Text(f"✅  {len(_hibp_cache)} breach dimuat\n", style="dim green")))

if __name__ == "__main__":
    main()
