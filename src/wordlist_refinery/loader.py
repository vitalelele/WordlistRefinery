"""
loader.py

This module handles memory-safe ingestion of massive wordlist files by
reading them line-by-line and batching them into Pandas DataFrames.

Each line is treated as a full password entry, regardless of its internal
characters (commas, quotes, semicolons, etc.), which makes this loader
robust against "dirty" real-world lists like rockyou.txt.

Author: Antonio Vitale
"""

from typing import Generator, List

import pandas as pd
import typer


class DataLoader:
    """
    Manages the loading of wordlists into Pandas DataFrames with
    memory-optimized settings (PyArrow-backed string column + chunk streaming).
    """

    def __init__(self, filepath: str, chunk_size: int = 100_000) -> None:
        """
        Initialize the loader.

        Args:
            filepath (str): Path to the wordlist file.
            chunk_size (int): Number of rows to process per batch.
        """
        self.filepath = filepath
        self.chunk_size = chunk_size

    def _batch_to_dataframe(self, batch: List[str]) -> pd.DataFrame:
        """
        Convert a list of password strings into a Pandas DataFrame
        with a PyArrow-backed string column.
        """
        # Use the new string[pyarrow] dtype so we still get the Arrow
        # memory advantages without relying on read_csv.
        series = pd.Series(batch, dtype="string[pyarrow]", name="password")
        return pd.DataFrame({"password": series})

    def load_chunks(self) -> Generator[pd.DataFrame, None, None]:
        """
        Yield DataFrames containing up to `chunk_size` passwords.

        This function reads the file line-by-line to keep memory usage low,
        and batches lines into DataFrames for downstream vectorized processing.

        Yields:
            pd.DataFrame: A dataframe with a single 'password' column.
        """
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                batch: List[str] = []

                for line in f:
                    # Remove only newline characters first
                    raw = line.rstrip("\r\n")

                    # Treat pure whitespace as empty as well
                    password = raw.strip()

                    if not password:
                        continue

                    batch.append(password)

                    if len(batch) >= self.chunk_size:
                        yield self._batch_to_dataframe(batch)
                        batch = []

                # Emit the last partial batch if any
                if batch:
                    yield self._batch_to_dataframe(batch)

        except FileNotFoundError:
            typer.secho(f"Error: File '{self.filepath}' not found.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        except Exception as e:
            typer.secho(f"Critical error during loading: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
