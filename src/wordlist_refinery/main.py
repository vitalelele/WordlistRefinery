"""
main.py

The entry point for the WordlistRefinery CLI. This module orchestrates
the interaction between the user, the DataLoader, and the PasswordAnalyzer.

It utilizes Typer for a modern, type-safe command line interface.

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


# Initialize Typer app and Rich console
app = typer.Typer(help="WordlistRefinery: High-Performance Password List Tool")
console = Console()

# Max rows allowed for ASCII output in file. Above this, CSV is used instead.
MAX_ASCII_ROWS_FOR_FILE = 5000

# Max preview rows printed to console per chunk
MAX_PREVIEW_ROWS = 20


def dataframe_to_ascii_table(df: pd.DataFrame) -> str:
    """
    Convert a DataFrame to a readable ASCII table for small datasets.
    """
    columns = [
        "password",
        "entropy",
        "strength",
        "has_upper",
        "has_lower",
        "has_digit",
        "has_special",
    ]

    df = df[columns].copy()
    df["entropy"] = df["entropy"].map(lambda x: f"{x:.2f}")
    df["has_upper"] = df["has_upper"].map(lambda x: "✓" if x else "✗")
    df["has_lower"] = df["has_lower"].map(lambda x: "✓" if x else "✗")
    df["has_digit"] = df["has_digit"].map(lambda x: "✓" if x else "✗")
    df["has_special"] = df["has_special"].map(lambda x: "✓" if x else "✗")

    return tabulate(df, headers="keys", tablefmt="grid")


def dataframe_to_markdown_table(df: pd.DataFrame) -> str:
    """
    Convert a DataFrame to a clean Markdown table for documentation-friendly output.
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


@app.command()
def analyze(
    input_file: str = typer.Argument(..., help="Path to the source wordlist"),
    output_file: str = typer.Option("refined_list.txt", help="Output file path"),
    min_entropy: float = typer.Option(0.0, help="Minimum Shannon entropy required"),
    wpa2_compliant: bool = typer.Option(False, help="Filter for WPA2 compliance"),
    chunk_size: int = typer.Option(100_000, help="Number of rows per chunk"),
    add_metadata: bool = typer.Option(False, help="Include entropy + complexity tags"),
    markdown_table: bool = typer.Option(False, help="Write Markdown table instead of ASCII/CSV"),
):
    """
    Ingest a wordlist, apply filters, and output a refined dataset.
    This tool processes the file in chunks to maintain low memory footprint.
    """

    # Check file existence
    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] Input file {input_file} not found.")
        raise typer.Exit(code=1)

    output_path = Path(output_file)
    console.print(f"[bold green]Starting process on:[/bold green] {input_path}")

    # Initialize output file (empty it if exists)
    with output_path.open("w", encoding="utf-8"):
        pass

    loader = DataLoader(str(input_path), chunk_size=chunk_size)
    total_passwords = 0
    start_time = time.time()

    # Decide ASCII or CSV for metadata based on the first chunk size
    use_ascii_output: Optional[bool] = None
    csv_header_written = False

    try:
        for chunk_df in loader.load_chunks():
            original_count = len(chunk_df)
            if chunk_df.empty:
                continue

            # Apply entropy calculation
            chunk_df["entropy"] = PasswordAnalyzer.vectorize_entropy(chunk_df["password"])

            # Filter by minimum entropy
            if min_entropy > 0:
                chunk_df = chunk_df[chunk_df["entropy"] >= min_entropy]
            if chunk_df.empty:
                console.print(f"Processed batch. Retained 0/{original_count} after entropy filter.")
                continue

            # WPA2 filtering
            if wpa2_compliant:
                chunk_df = PasswordAnalyzer.filter_wpa2_compliant(chunk_df, "password")
            if chunk_df.empty:
                console.print(f"Processed batch. Retained 0/{original_count} after WPA2 filter.")
                continue

            # Add metadata
            if add_metadata:
                chunk_df = PasswordAnalyzer.tag_complexity(chunk_df, "password")
                chunk_df["strength"] = chunk_df["entropy"].apply(
                    PasswordAnalyzer.classify_strength
                )

                # Rich table preview
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
                        f"[yellow]Preview truncated:[/yellow] showing first "
                        f"{MAX_PREVIEW_ROWS} rows. Full chunk written to {output_file}."
                    )

                # Decide ASCII vs CSV only on first chunk
                if use_ascii_output is None:
                    use_ascii_output = original_count <= MAX_ASCII_ROWS_FOR_FILE

            # Output writing
            if add_metadata:
                if markdown_table:
                    md = dataframe_to_markdown_table(chunk_df)
                    with output_path.open("a", encoding="utf-8") as f:
                        f.write(md + "\n\n")

                else:
                    if use_ascii_output:
                        ascii_table = dataframe_to_ascii_table(chunk_df)
                        with output_path.open("a", encoding="utf-8") as f:
                            f.write(ascii_table + "\n\n")

                    else:
                        # CSV output for large datasets (clean, no blank lines)
                        with output_path.open("a", encoding="utf-8", newline="") as f:
                            chunk_df.to_csv(
                                f,
                                header=not csv_header_written,
                                index=False,
                                lineterminator="\n",
                            )
                            csv_header_written = True

            else:
                # Raw passwords only (TXT)
                chunk_df["password"].to_csv(
                    output_path,
                    mode="a",
                    header=False,
                    index=False,
                    encoding="utf-8",
                    lineterminator="\n",
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
