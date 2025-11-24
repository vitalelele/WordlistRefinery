"""
main.py

Entry point for the WordlistRefinery CLI.

Features:
- Chunked ingestion of large wordlists
- Entropy calculation and filtering
- WPA2 compliance filtering
- Rich table preview in console
- ASCII table export for small wordlists
- CSV export for large wordlists
- Markdown table export with --markdown-table
- Complexity tagging and strength classification

Author: Antonio Vitale
"""

import time
from pathlib import Path
from typing import Optional

import pandas as pd
import typer
from rich.console import Console
from rich.table import Table
from tabulate import tabulate

from wordlist_refinery.loader import DataLoader
from wordlist_refinery.analyzer import PasswordAnalyzer


app = typer.Typer(help="WordlistRefinery: High-Performance Password List Tool")
console = Console()

# How many rows in the FIRST chunk we consider "small" for ASCII file output
MAX_ASCII_ROWS_FOR_FILE = 5_000
# How many rows to show in console per chunk
MAX_PREVIEW_ROWS = 20


# ---------------------------------------------------------
# ASCII TABLE RENDERER (for small datasets)
# ---------------------------------------------------------
def dataframe_to_ascii_table(df: pd.DataFrame) -> str:
    """
    Convert a DataFrame to an ASCII table suitable for .txt output.
    Intended for small datasets (e.g., demo, debugging).
    """
    cols = [
        "password",
        "entropy",
        "strength",
        "has_upper",
        "has_lower",
        "has_digit",
        "has_special",
    ]

    df = df[cols].copy()
    df["entropy"] = df["entropy"].map(lambda x: f"{x:.2f}")

    df["has_upper"] = df["has_upper"].map(lambda x: "✓" if x else "✗")
    df["has_lower"] = df["has_lower"].map(lambda x: "✓" if x else "✗")
    df["has_digit"] = df["has_digit"].map(lambda x: "✓" if x else "✗")
    df["has_special"] = df["has_special"].map(lambda x: "✓" if x else "✗")

    return tabulate(df, headers="keys", tablefmt="grid")


# ---------------------------------------------------------
# MARKDOWN TABLE RENDERER
# ---------------------------------------------------------
def dataframe_to_markdown_table(df: pd.DataFrame) -> str:
    """
    Convert a DataFrame into a clean Markdown table.
    """
    cols = [
        "password",
        "entropy",
        "strength",
        "has_upper",
        "has_lower",
        "has_digit",
        "has_special",
    ]

    df = df[cols].copy()
    df["entropy"] = df["entropy"].map(lambda x: f"{x:.2f}")

    header = "|" + "|".join(cols) + "|\n"
    sep = "|" + "|".join("---" for _ in cols) + "|\n"

    rows = []
    for _, row in df.iterrows():
        vals = [str(row[c]) for c in cols]
        rows.append("|" + "|".join(vals) + "|")

    return header + sep + "\n".join(rows)


# ---------------------------------------------------------
# MAIN CLI COMMAND
# ---------------------------------------------------------
@app.command()
def analyze(
    input_file: str = typer.Argument(..., help="Path to the source wordlist file"),
    output_file: str = typer.Option("refined_list.txt", help="Output file path"),
    min_entropy: float = typer.Option(0.0, help="Minimum Shannon entropy required"),
    wpa2_compliant: bool = typer.Option(
        False, help="Keep only WPA2-compliant passwords (8-63 printable ASCII)"
    ),
    chunk_size: int = typer.Option(100_000, help="Number of rows per batch"),
    add_metadata: bool = typer.Option(
        False, help="Include complexity tags, strength labels, and entropy values"
    ),
    markdown_table: bool = typer.Option(
        False,
        help="Write Markdown tables to the output file (requires --add-metadata)",
    ),
) -> None:
    """
    Process a wordlist in chunks, apply filters, print Rich tables in console,
    and export refined output as:

    - raw passwords (default, no --add-metadata)
    - ASCII tables for small datasets (with --add-metadata)
    - CSV for large datasets (with --add-metadata)
    - Markdown tables (with --add-metadata --markdown-table)
    """

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] File '{input_file}' not found.")
        raise typer.Exit(code=1)

    output_path = Path(output_file)

    if markdown_table and not add_metadata:
        console.print(
            "[bold yellow]Warning:[/bold yellow] --markdown-table only works with --add-metadata."
        )

    console.print(f"[bold green]Starting process on:[/bold green] {input_path}")

    # Truncate output file before starting (we always append chunk-by-chunk)
    with output_path.open("w", encoding="utf-8") as f:
        pass

    total_passwords = 0
    start_time = time.time()

    loader = DataLoader(str(input_path), chunk_size=chunk_size)

    # Decide ONCE, after the first chunk, whether to use ASCII or CSV for metadata
    use_ascii_output: Optional[bool] = None
    csv_header_written = False

    try:
        for chunk_df in loader.load_chunks():
            original_count = len(chunk_df)
            if chunk_df.empty:
                continue

            # 1. Entropy calculation
            chunk_df["entropy"] = PasswordAnalyzer.vectorize_entropy(
                chunk_df["password"]
            )

            # 2. Entropy filter
            if min_entropy > 0:
                chunk_df = chunk_df[chunk_df["entropy"] >= min_entropy]
            if chunk_df.empty:
                console.print(
                    f"Processed batch. Retained 0/{original_count} after entropy filter."
                )
                continue

            # 3. WPA2 filter
            if wpa2_compliant:
                chunk_df = PasswordAnalyzer.filter_wpa2_compliant(
                    chunk_df, "password"
                )
            if chunk_df.empty:
                console.print(
                    f"Processed batch. Retained 0/{original_count} after WPA2 filter."
                )
                continue

            # 4. Add metadata
            if add_metadata:
                chunk_df = PasswordAnalyzer.tag_complexity(chunk_df, "password")
                chunk_df["strength"] = chunk_df["entropy"].apply(
                    PasswordAnalyzer.classify_strength
                )

                # ---------------------- RICH PREVIEW IN CONSOLE ----------------------
                table = Table(
                    title="WordlistRefinery - Chunk Preview",
                    show_header=True,
                    header_style="bold magenta",
                )
                table.add_column("Password", style="cyan", no_wrap=True)
                table.add_column("Entropy", justify="right")
                table.add_column("Strength")
                table.add_column("Upper", justify="center")
                table.add_column("Lower", justify="center")
                table.add_column("Digit", justify="center")
                table.add_column("Special", justify="center")

                preview_df = chunk_df.head(MAX_PREVIEW_ROWS)

                for _, row in preview_df.iterrows():
                    table.add_row(
                        str(row["password"]),
                        f"{row['entropy']:.2f}",
                        str(row["strength"]),
                        "✓" if row["has_upper"] else "·",
                        "✓" if row["has_lower"] else "·",
                        "✓" if row["has_digit"] else "·",
                        "✓" if row["has_special"] else "·",
                    )

                console.print(table)

                if len(chunk_df) > MAX_PREVIEW_ROWS:
                    console.print(
                        f"[bold yellow]Preview truncated:[/bold yellow] "
                        f"showing first {MAX_PREVIEW_ROWS} rows of this chunk. "
                        f"Full results have been written to [bold]{output_path}[/bold]."
                    )

                # ---------------------- DECIDE ASCII vs CSV (once) -------------------
                if use_ascii_output is None:
                    # Decision based on the FIRST chunk size (before filters):
                    # - small wordlists (like demos/tests) -> ASCII in file
                    # - large wordlists (rockyou, leaks)  -> CSV in file
                    use_ascii_output = original_count <= MAX_ASCII_ROWS_FOR_FILE

            # 5. Output writing
            if add_metadata:
                if markdown_table:
                    # Explicit markdown mode: user asked for it, always use Markdown
                    md = dataframe_to_markdown_table(chunk_df)
                    with output_path.open("a", encoding="utf-8") as f:
                        f.write(md + "\n\n")

                else:
                    # Auto: ASCII for small datasets, CSV for large ones
                    if use_ascii_output:
                        ascii_table = dataframe_to_ascii_table(chunk_df)
                        with output_path.open("a", encoding="utf-8") as f:
                            f.write(ascii_table + "\n\n")
                    else:
                        # Large dataset mode: efficient CSV output
                        with output_path.open("a", encoding="utf-8") as f:
                            if not csv_header_written:
                                chunk_df.to_csv(
                                    f,
                                    header=True,
                                    index=False,
                                )
                                csv_header_written = True
                            else:
                                chunk_df.to_csv(
                                    f,
                                    header=False,
                                    index=False,
                                )

            else:
                # Raw password-only output (one per line)
                chunk_df["password"].to_csv(
                    output_path,
                    mode="a",
                    header=False,
                    index=False,
                    encoding="utf-8",
                )

            total_passwords += len(chunk_df)
            console.print(
                f"Processed batch. Retained {len(chunk_df)}/{original_count} candidates."
            )

    except Exception as e:
        console.print(f"[bold red]Processing failed:[/bold red] {e}")
        raise typer.Exit(1)

    elapsed = time.time() - start_time
    console.print(f"[bold green]Success![/bold green] Saved to {output_path}")
    console.print(f"Total retained: {total_passwords}")
    console.print(f"Time elapsed: {elapsed:.2f} seconds")


if __name__ == "__main__":
    app()
