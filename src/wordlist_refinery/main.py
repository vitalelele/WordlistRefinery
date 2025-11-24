"""
main.py

Entry point for the WordlistRefinery CLI.

Features:
- Chunked ingestion of large wordlists
- Entropy calculation and filtering
- WPA2 compliance filtering
- Rich table preview in console
- ASCII table export for .txt files
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


# ASCII table renderer
def dataframe_to_ascii_table(df: pd.DataFrame) -> str:
    """
    Convert a DataFrame to an ASCII table suitable for .txt output.
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

# markdown table renderer
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


# main CLI command
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
    and export refined output as ASCII tables, Markdown tables, or raw passwords.
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

    with output_path.open("w", encoding="utf-8") as f:
        pass  # file will be appended chunk-by-chunk

    total_passwords = 0
    start_time = time.time()

    loader = DataLoader(str(input_path), chunk_size=chunk_size)

    try:
        for chunk_df in loader.load_chunks():
            original_count = len(chunk_df)
            if chunk_df.empty:
                continue

            # Entropy calculation
            chunk_df["entropy"] = PasswordAnalyzer.vectorize_entropy(
                chunk_df["password"]
            )

            # Entropy filter
            if min_entropy > 0:
                chunk_df = chunk_df[chunk_df["entropy"] >= min_entropy]
            if chunk_df.empty:
                console.print(
                    f"Processed batch. Retained 0/{original_count} after entropy filter."
                )
                continue

            # WPA2 filter
            if wpa2_compliant:
                chunk_df = PasswordAnalyzer.filter_wpa2_compliant(
                    chunk_df, "password"
                )
            if chunk_df.empty:
                console.print(
                    f"Processed batch. Retained 0/{original_count} after WPA2 filter."
                )
                continue

            # Add metadata
            if add_metadata:
                chunk_df = PasswordAnalyzer.tag_complexity(chunk_df, "password")
                chunk_df["strength"] = chunk_df["entropy"].apply(
                    PasswordAnalyzer.classify_strength
                )

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

                for _, row in chunk_df.head(20).iterrows():
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

            # 5. Output writing
            if add_metadata:
                if markdown_table:
                    md = dataframe_to_markdown_table(chunk_df)
                    with output_path.open("a", encoding="utf-8") as f:
                        f.write(md + "\n\n")
                else:
                    ascii_table = dataframe_to_ascii_table(chunk_df)
                    with output_path.open("a", encoding="utf-8") as f:
                        f.write(ascii_table + "\n\n")
            else:
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
    console.print(f"[bold green]Success![/bold_green] Saved to {output_path}")
    console.print(f"Total retained: {total_passwords}")
    console.print(f"Time elapsed: {elapsed:.2f} seconds")


if __name__ == "__main__":
    app()
