"""
main.py

Entry point for the WordlistRefinery CLI.

Author: Antonio Vitale
"""

import time
from pathlib import Path

import typer
from rich.console import Console

from wordlist_refinery.loader import DataLoader
from wordlist_refinery.analyzer import PasswordAnalyzer

app = typer.Typer(help="WordlistRefinery: High-Performance Password List Tool")
console = Console()


@app.command()
def analyze(
    input_file: str = typer.Argument(..., help="Path to the source wordlist"),
    output_file: str = typer.Option("refined_list.txt", help="Output file path"),
    min_entropy: float = typer.Option(0.0, help="Minimum Shannon Entropy required"),
    wpa2_compliant: bool = typer.Option(False, help="Filter for WPA2 (8-63 printable chars)"),
    chunk_size: int = typer.Option(100_000, help="Rows to process per batch"),
    add_metadata: bool = typer.Option(False, help="Output CSV with complexity tags instead of raw list"),
) -> None:
    """
    Ingest a wordlist, apply filters, and output a refined dataset.
    """

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] Input file {input_file} not found.")
        raise typer.Exit(code=1)

    output_path = Path(output_file)

    console.print(f"[bold green]Starting process on:[/bold green] {input_path}")

    # Truncate output file and optionally write CSV header
    with output_path.open("w", encoding="utf-8") as f:
        if add_metadata:
            f.write("password,entropy,strength,has_upper,has_lower,has_digit,has_special\n")

    total_passwords = 0
    start_time = time.time()

    loader = DataLoader(str(input_path), chunk_size=chunk_size)

    try:
        for chunk_df in loader.load_chunks():
            original_count = len(chunk_df)

            # 1. Entropy
            chunk_df["entropy"] = PasswordAnalyzer.vectorize_entropy(chunk_df["password"])

            # 2. Min entropy
            if min_entropy > 0:
                chunk_df = chunk_df[chunk_df["entropy"] >= min_entropy]

            # 3. WPA2 filter
            if wpa2_compliant:
                chunk_df = PasswordAnalyzer.filter_wpa2_compliant(chunk_df, "password")

            # 4. Metadata
            if add_metadata:
                chunk_df = PasswordAnalyzer.tag_complexity(chunk_df, "password")
                chunk_df["strength"] = chunk_df["entropy"].apply(
                    PasswordAnalyzer.classify_strength
                )

            # 5. Write out
            if not chunk_df.empty:
                if add_metadata:
                    chunk_df.to_csv(
                        output_path,
                        mode="a",
                        header=False,
                        index=False,
                        encoding="utf-8",
                    )
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
        console.print(f"[bold red]Processing Failed:[/bold red] {e}")
        raise typer.Exit(1)

    elapsed = time.time() - start_time
    console.print(f"[bold green]Success![/bold green] Refined list saved to {output_path}")
    console.print(f"Total candidates retained: {total_passwords}")
    console.print(f"Time elapsed: {elapsed:.2f} seconds")


if __name__ == "__main__":
    app()
