"""
loader.py

This module handles the ingestion of massive text files using Pandas
chunking and the PyArrow backend. It is designed to be memory-safe,
preventing OOM (Out of Memory) errors even when processing multi-gigabyte
wordlists.

Author: Antonio Vitale
"""
from typing import Iterator
import pandas as pd
import typer

class DataLoader:
    """
    Manages the loading of wordlists into Pandas DataFrames with 
    memory-optimized settings.
    """

    def __init__(self, filepath: str, chunk_size: int = 100_000):
        """
        Initialize the loader.

        Args:
            filepath (str): Path to the wordlist file.
            chunk_size (int): Number of rows to process per batch. 
                              Default 100k balances memory usage vs I/O overhead.
        """
        self.filepath = filepath
        self.chunk_size = chunk_size

    def load_chunks(self) -> Generator:
        """
        Yields chunks of the wordlist as DataFrames.

        This method utilizes the 'pyarrow' dtype backend for significant
        memory savings on string data.
        
        Returns:
            Generator: A generator yielding dataframes.
        
        Raises:
            FileNotFoundError: If the filepath is invalid.
            pd.errors.ParserError: If the CSV structure is malformed.
        """
        try:
            # We treat wordlists as single-column CSVs. 
            # 'header=None' implies the file has no header row.
            # 'names=['password']' assigns a column name.
            # 'dtype_backend="pyarrow"' enables modern Arrow-backed strings.
            # 'quoting=3' (QUOTE_NONE) prevents parsing errors on quotes inside passwords.
            
            with pd.read_csv(
                self.filepath,
                header=None,
                names=["password"],
                chunksize=self.chunk_size,
                engine="pyarrow",  # Use the pyarrow engine for speed [3]
                dtype_backend="pyarrow", # Enforce arrow types for memory efficiency
                on_bad_lines="warn", # Skip malformed lines, warn user
                quoting=3 # CSV.QUOTE_NONE: Crucial for passwords containing " or '
            ) as reader:
                
                for i, chunk in enumerate(reader):
                    # Drop any NaN values immediately to maintain data integrity
                    clean_chunk = chunk.dropna(subset=["password"])
                    yield clean_chunk
        # Handle file not found and parsing errors gracefully
        except FileNotFoundError:
            typer.secho(f"Error: File '{self.filepath}' not found.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        except Exception as e:
            typer.secho(f"Critical Error during loading: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
