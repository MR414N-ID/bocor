# lang: Python, file: bocor.py, target: Python 3.8+
# deps: pip install rich requests
# run: python bocor.py

import hashlib
import time
import requests
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()

ASCII_ART = """
███╗   ███╗██████╗ ██╗  ██╗ ██╗ ██╗  ███╗  ███╗       ██╗██████╗ 
████╗ ████║██╔══██╗██║  ██║ ██║ ██║ ██╔██╗ ██╔██╗      ██║██╔══██╗
██╔████╔██║██████╔╝███████║ ███████║██╔╝██╗██╔╝██╗     ██║██║  ██║
██║╚██╔╝██║██╔══██╗╚════██║ ╚════██║██████╔╝██████╔╝   ██║██║  ██║
██║ ╚═╝ ██║██║  ██║      ██║      ██║╚═██╔═╝╚═██╔═╝    ██║██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝      ╚═╝  ╚═╝    ╚═╝     ╚═╝╚═════╝ 
"""

COLORS = ["red", "yellow", "green", "cyan", "blue", "magenta"]

# ── banner ──────────────────────────────────────────────────────────────────

def print_banner():
    console.clear()
    lines = ASCII_ART.strip().split("\n")
    colored_art = Text()
    for i, line in enumerate(lines):
        colored_art.append(line + "\n", style=f"bold {COLORS[i % len(COLORS)]}")
    console.print(Align.center(colored_art))

    subtitle = Text()
    for i, ch in enumerate("[ MR414N-ID | Data Breach Checker | v1.0 ]"):
        subtitle.append(ch, style=f"bold {COLORS[i % len(COLORS)]}")
    console.print(Align.center(subtitle))
    console.print()

    info = Text(justify="center")
    info.append("🔍  Cek apakah datamu pernah bocor di internet\n", style="bold white")
    info.append("📧  Email  •  🪪  NIK  •  📱  No. HP  •  👤  Username\n", style="dim white")
    info.append("🔒  Data tidak dikirim utuh — dilindungi hashing lokal", style="dim cyan")
    console.print(Align.center(Panel(info, border_style="bright_cyan", padding=(1, 4), width=72)))
    console.print()

# ── HIBP breach metadata cache ───────────────────────────────────────────────

_hibp_cache: dict = {}

def load_hibp_metadata():
    global _hibp_cache
    if _hibp_cache:
        return
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "bocor-py/1.0"},
            timeout=10,
        )
        if r.status_code == 200:
            for b in r.json():
                _hibp_cache[b["Name"].lower()] = b
    except Exception:
        pass

def get_hibp_meta(breach_name: str) -> dict:
    return _hibp_cache.get(breach_name.lower(), {})

# ── XposedOrNot ──────────────────────────────────────────────────────────────

def xon_check_email(email: str) -> list[str]:
    """Return list of breach names from XposedOrNot free API."""
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers={"User-Agent": "bocor-py/1.0"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            # format: {"breaches": [["Adobe"], ["LinkedIn"]], "email": "..."}
            raw = data.get("breaches", [])
            return [b[0] if isinstance(b, list) else b for b in raw]
        elif r.status_code == 404:
            return []
    except Exception:
        pass
    return None  # None = error, [] = clean

def xon_analytics(email: str) -> dict:
    """Return breach analytics detail dari XposedOrNot."""
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
            headers={"User-Agent": "bocor-py/1.0"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

# ── severity helper ──────────────────────────────────────────────────────────

SENSITIVE_FIELDS = {
    "passwords", "password", "credit cards", "bank account numbers",
    "phone numbers", "physical addresses", "dates of birth",
    "government id numbers", "nik", "social security numbers",
}

def severity(data_classes: list[str]) -> tuple[str, str]:
    dc_lower = {d.lower() for d in data_classes}
    if dc_lower & SENSITIVE_FIELDS:
        return "TINGGI", "bold red"
    if "email addresses" in dc_lower and len(dc_lower) > 2:
        return "SEDANG", "bold yellow"
    return "RENDAH", "bold green"

# ── display hasil ────────────────────────────────────────────────────────────

def display_results(email: str, breach_names: list[str], analytics: dict):
    console.print()

    if not breach_names:
        console.print(Align.center(
            Panel(
                Align.center(Text("✅  Tidak ditemukan di breach manapun", style="bold green")),
                border_style="green", padding=(1, 4), width=60
            )
        ))
        return

    # header ringkasan
    total = len(breach_names)
    summary = Text(justify="center")
    summary.append(f"⚠️  {email}\n", style="bold white")
    summary.append(f"ditemukan di ", style="white")
    summary.append(f"{total} breach", style="bold red")
    summary.append(f" yang diketahui", style="white")
    console.print(Align.center(
        Panel(summary, border_style="red", padding=(1, 4), width=72)
    ))
    console.print()

    # tabel per breach
    table = Table(
        box=box.ROUNDED,
        border_style="bright_cyan",
        header_style="bold cyan",
        show_lines=True,
        expand=True,
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
        sev_text = Text(sev_label, style=sev_style)

        table.add_row(name, year, pwn_count, fields_text, sev_text)

    console.print(table)
    console.print()

    # tips
    tips = Text(justify="center")
    tips.append("💡 Tips: ", style="bold cyan")
    tips.append("Ganti password di semua akun yang terdampak. Aktifkan 2FA.", style="white")
    console.print(Align.center(tips))
    console.print()

# ── placeholder NIK / HP / username ─────────────────────────────────────────

def check_nik(nik: str):
    console.print(Panel(
        Align.center(Text(
            "🪪  NIK — database lokal belum tersedia\n"
            "Tambahkan dataset ke local_db/nik.db untuk mengaktifkan fitur ini.",
            style="dim yellow", justify="center"
        )),
        border_style="yellow", padding=(1, 2)
    ))

def check_phone(phone: str):
    console.print(Panel(
        Align.center(Text(
            "📱  No. HP — database lokal belum tersedia\n"
            "Tambahkan dataset ke local_db/phone.db untuk mengaktifkan fitur ini.",
            style="dim yellow", justify="center"
        )),
        border_style="yellow", padding=(1, 2)
    ))

def check_username(username: str):
    # XposedOrNot juga support username check
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{username}",
            headers={"User-Agent": "bocor-py/1.0"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            names = [b[0] if isinstance(b, list) else b for b in data.get("breaches", [])]
            if names:
                console.print(Panel(
                    Text(f"👤  Username '{username}' ditemukan di: {', '.join(names)}", style="bold red"),
                    border_style="red", padding=(1, 2)
                ))
            else:
                console.print(Panel(
                    Text(f"✅  Username '{username}' tidak ditemukan di breach manapun", style="bold green"),
                    border_style="green", padding=(1, 2)
                ))
        elif r.status_code == 404:
            console.print(Panel(
                Text(f"✅  Username '{username}' tidak ditemukan di breach manapun", style="bold green"),
                border_style="green", padding=(1, 2)
            ))
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")

# ── menu utama ───────────────────────────────────────────────────────────────

def show_menu():
    menu = Text(justify="center")
    menu.append("  [1]", style="bold cyan")
    menu.append(" Cek Email        ", style="white")
    menu.append("[2]", style="bold cyan")
    menu.append(" Cek NIK        ", style="white")
    menu.append("[3]", style="bold cyan")
    menu.append(" Cek No. HP      ", style="white")
    menu.append("[4]", style="bold cyan")
    menu.append(" Cek Username    ", style="white")
    menu.append("[0]", style="bold red")
    menu.append(" Keluar  ", style="white")
    console.print(Align.center(Panel(menu, border_style="bright_cyan", padding=(0, 2), width=72)))
    console.print()

def main():
    print_banner()

    console.print(Align.center(
        Text("⏳  Memuat breach database...", style="dim white")
    ))
    load_hibp_metadata()
    console.print(Align.center(
        Text(f"✅  {len(_hibp_cache)} breach dimuat dari HIBP\n", style="dim green")
    ))

    while True:
        show_menu()
        pilihan = Prompt.ask(
            "[bold cyan]Pilih[/bold cyan]",
            choices=["0", "1", "2", "3", "4"],
            default="1"
        )

        if pilihan == "0":
            console.print("\n[dim]bye.[/dim]\n")
            break

        elif pilihan == "1":
            email = Prompt.ask("[bold white]Masukkan email[/bold white]").strip()
            if not email:
                continue
            console.print(f"\n[dim]🔍 Mencari breach untuk {email}...[/dim]")
            breach_names = xon_check_email(email)
            if breach_names is None:
                console.print("[red]⚠️  Gagal terhubung ke XposedOrNot. Cek koneksi internet.[/red]")
            else:
                analytics = xon_analytics(email) if breach_names else {}
                display_results(email, breach_names, analytics)

        elif pilihan == "2":
            nik = Prompt.ask("[bold white]Masukkan NIK[/bold white]").strip()
            check_nik(nik)

        elif pilihan == "3":
            phone = Prompt.ask("[bold white]Masukkan No. HP[/bold white]").strip()
            check_phone(phone)

        elif pilihan == "4":
            username = Prompt.ask("[bold white]Masukkan Username[/bold white]").strip()
            check_username(username)

        console.print()
        input("[dim]Tekan Enter untuk lanjut...[/dim]")
        print_banner()
        console.print(Align.center(
            Text(f"✅  {len(_hibp_cache)} breach dimuat\n", style="dim green")
        ))

if __name__ == "__main__":
    main()
