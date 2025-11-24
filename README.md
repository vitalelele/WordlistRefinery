# Introduction

Processing large password datasets has become a fundamental requirement in modern offensive security, digital forensics, and credential auditing. Traditional utilities, ad-hoc scripts, or naïve Python loops often fail when dealing with real-world breach data: millions of lines, malformed entries, mixed encodings, and memory-heavy operations quickly cause slowdowns, crashes, or inconsistent results.

**WordlistRefinery** is a high-performance command-line engine engineered specifically to solve this problem.

Its purpose is to take raw, unstructured, often noisy password lists and transform them into clean, analyzable, and attack-ready datasets — all while maintaining a low memory footprint and high processing speed. Whether you're preparing a refined wordlist for a penetration test, performing entropy-based research, or analyzing a breach corpus, WordlistRefinery provides a robust, scalable foundation.

### Why process large datasets?

Real-world password leaks such as *rockyou.txt* contain:

- millions of repeated passwords  
- invalid or malformed entries  
- non-ASCII characters that break certain protocols  
- extremely weak passwords  
- noisy data that slows down cracking tools  

This noise wastes time, resources, and reduces the effectiveness of password audits.

### What WordlistRefinery provides

WordlistRefinery solves these problems through:

- **Chunk-based streaming** for safe processing of multi-gigabyte lists  
- **PyArrow-backed Pandas strings**, reducing memory usage by up to 70%  
- **Vectorized entropy computation** for scoring password strength at scale  
- **Complexity and policy filters**, including WPA2 compliance  
- **Automatic output optimization** (ASCII tables for small sets, CSV for large datasets)  
- **Human-readable previews** using Rich-powered console tables  
- **Clean TXT/CSV/Markdown exports**, ready for cracking tools or analytical pipelines  

By turning chaotic raw data into structured intelligence, WordlistRefinery becomes a valuable asset for:

- penetration testers  
- red teams  
- SOC analysts  
- security researchers  
- digital forensics professionals  
- students learning password and entropy analysis  

WordlistRefinery transforms raw credential dumps into **efficient, targeted, and actionable datasets**, enabling repeatable and scalable workflows instead of error-prone manual cleanup.

# Installation

WordlistRefinery is distributed as a standard Python package and can be installed in any environment that supports **Python 3.10+**.

Below are the recommended installation methods depending on your workflow.

---

## 1. Clone the Repository

Begin by cloning the project:

```bash
git clone https://github.com/vitalelele/WordlistRefinery.git
cd WordlistRefinery
````

---

## 2. Create a Virtual Environment (Recommended)

Using a virtual environment keeps dependencies isolated:

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### Windows (PowerShell)

```powershell
python -m venv venv
venv\Scripts\activate
```

---

## 3. Install the Package in Editable Mode

Editable mode (`-e`) lets you run and develop the tool directly from the repository:

```bash
pip install -e .
```

This will:

* install all dependencies declared in `pyproject.toml`
* register the CLI command `wordlist-refinery`
* allow you to modify the source code without reinstalling

---

## 4. Verify Installation

Run:

```bash
wordlist-refinery --help
```

You should see the full CLI help screen:

```
Usage: wordlist-refinery [OPTIONS] INPUT_FILE

Ingest a wordlist, apply filters, and output a refined dataset.
```
<img width="1670" height="395" alt="image" src="https://github.com/user-attachments/assets/290d36de-0997-4fce-bf95-f46382e58e57" />

If you see this, the installation was successful.

---

## Optional: Installing Development Requirements

To contribute to the project (testing, linting, etc.) you may install additional developer tools:

```bash
pip install pytest ruff mypy
```

---

## Note for Windows Users

If PowerShell refuses to run the command, you may need to allow execution of local scripts:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Optional: Running Example Wordlists

The repository includes an `examples/` directory with ready-made datasets:

```bash
wordlist-refinery examples/small_list.txt --add-metadata
```

or:

```bash
wordlist-refinery examples/rockyou_subset_1k.txt --add-metadata --output-file out.csv
```

These are useful for confirming the tool works correctly before running it on large lists like *rockyou.txt*.


# Features & Command Overview

WordlistRefinery provides a rich set of features designed to process, filter, analyze, and refine massive password datasets in a safe and efficient way. This section explains every capability of the tool, along with usage examples and expected outputs.

---

## Core Features

### 1. Chunk-Based Streaming  
Processes extremely large wordlists (e.g., rockyou.txt with 14M+ entries) without loading them fully into memory.  
Each chunk is processed independently, ensuring stable RAM usage.

**Why it matters:**  
Avoids memory exhaustion and allows the tool to run even on modest hardware.

---

### 2. Shannon Entropy Calculation  
Computes entropy for each password to estimate complexity and randomness.

Example:  
- `aaaaaa` → entropy = **0.00** (very predictable)  
- `Tr0ub4dor&3` → entropy ≈ **3.28**  
- `VeryStrongPassword123!!!` → entropy ≈ **4.02**

Used to classify passwords into:

- **Very Weak**
- **Weak**
- **Moderate**
- **Strong**

---

### 3. WPA2 Compliance Filtering  
Keeps only passwords valid for WPA2-PSK:

- Length between **8–63**
- Only printable ASCII characters

Useful for generating Wi-Fi attack wordlists.

Example:

```bash
wordlist-refinery rockyou.txt --wpa2-compliant --output-file wpa2_clean.txt
````

---

### 4. Complexity Tagging

Adds boolean indicators:

* `has_upper`
* `has_lower`
* `has_digit`
* `has_special`

Example row:

```
password: Tr0ub4dor&3
has_upper: True
has_lower: True
has_digit: True
has_special: True
```

---

### 5. Adaptable Output Format

Output format automatically adapts to dataset size:

| Dataset Size        | Output                          |
| ------------------- | ------------------------------- |
| Small (≤ 5000 rows) | ASCII Table                     |
| Large (> 5000 rows) | CSV                             |
| `--markdown-table`  | Markdown table                  |
| No metadata         | Raw TXT (one password per line) |

This ensures both readability and performance.

---

### 6. Rich Console Preview

Each processed chunk is shown in the terminal using a visually appealing Rich table.

If the chunk contains more than 20 rows, the preview is truncated:

```
Preview truncated: showing first 20 rows of this chunk.
```

---

### 7. Markdown Export

Generate documentation-ready tables:

```bash
wordlist-refinery testlist.txt --add-metadata --markdown-table --output-file analysis.md
```

---

## Command Overview

### Base Syntax

```
wordlist-refinery [OPTIONS] INPUT_FILE
```

---

## Option Reference

| Option                | Type   | Description                                  |
| --------------------- | ------ | -------------------------------------------- |
| `--output-file PATH`  | string | Output file path (TXT/CSV/MD)                |
| `--min-entropy FLOAT` | float  | Minimum entropy threshold                    |
| `--wpa2-compliant`    | flag   | Keep only WPA2-valid passwords               |
| `--chunk-size INT`    | int    | Number of rows processed per chunk           |
| `--add-metadata`      | flag   | Adds entropy, strength, complexity tags      |
| `--markdown-table`    | flag   | Outputs a Markdown table (requires metadata) |
| `--help`              | flag   | Display help                                 |

---

# Usage Examples

## Example 1 — Basic Processing

Process a small list and output only passwords that remain after filtering.

```bash
wordlist-refinery examples/small_list.txt
```

Output (`small_list_refined.txt`):

```
password
123456
short
Tr0ub4dor&3
...
```

---

## Example 2 — Entropy Filtering

Keep only passwords with entropy ≥ 3.0 bits.

```bash
wordlist-refinery examples/small_list.txt --min-entropy 3.0
```

Preview (console):

```
Password     Entropy   Strength
-----------  --------  ----------
Tr0ub4dor&3    3.28    Weak
VeryStrong...   4.02   Moderate
```

---

## Example 3 — WPA2 Wordlist Generation

```bash
wordlist-refinery rockyou.txt --wpa2-compliant --output-file wpa2_clean.txt
```

Output:

* Only passwords 8–63 chars
* Only printable ASCII
* Ready for Wi-Fi cracking tools like aircrack-ng or hashcat

---

## Example 4 — Full Metadata Extraction (ASCII Table)

For small datasets:

```bash
wordlist-refinery examples/small_list.txt --add-metadata
```

Output (ASCII):

```
+----+--------------------------+-----------+------------+---------+---------+
| id | password                 | entropy   | strength   | upper   | digit   |
+----+--------------------------+-----------+------------+---------+---------+
|  0 | password                 | 2.75      | Weak       | ✗       | ✗       |
|  1 | Tr0ub4dor&3              | 3.28      | Weak       | ✓       | ✓       |
...
```
<img width="765" height="393" alt="image" src="https://github.com/user-attachments/assets/62296d41-8b6e-4671-83e3-b76414f84f13" />
---

## Example 5 — Full Metadata Extraction (CSV for Large Sets)

```bash
wordlist-refinery rockyou.txt --add-metadata --output-file rockyou_meta.csv
```

Output (true CSV):

```
password,entropy,strength,has_upper,has_lower,has_digit,has_special
123456,2.58,Weak,False,False,True,False
password,2.75,Weak,False,True,False,False
...
```

Perfect for data science, ML analysis, or import into Excel/Jupyter.

---

## Example 6 — Markdown Output for Reports

```bash
wordlist-refinery examples/small_list.txt --add-metadata --markdown-table --output-file analysis.md
```

Markdown table:

```markdown
|password|entropy|strength|has_upper|has_lower|has_digit|has_special|
|---|---|---|---|---|---|---|
|password|2.75|Weak|False|True|False|False|
|Tr0ub4dor&3|3.28|Weak|True|True|True|True|
```

Perfect for documentation, PDF export, or GitHub pages.

---

## Example 7 — Processing a Large List (rockyou.txt)

```bash
wordlist-refinery rockyou.txt --add-metadata --output-file refined_rockyou.csv
```

Console output (preview):

<img width="764" height="618" alt="image" src="https://github.com/user-attachments/assets/21977bcf-6b18-4a7c-af0c-7e00c8d2ece5" />


Output:

* CSV file with millions of entries
* No ASCII tables
* Fully compatible with Excel / Pandas / Jupyter

---

## Performance & Design Rationale

WordlistRefinery was designed to process extremely large password datasets while maintaining predictable memory usage and consistent performance. Traditional scripts often fail due to Python's internal memory model and the cost of holding millions of strings in RAM. This section explains the engineering choices that allow the tool to scale efficiently.

### Streaming Processing Model
The tool never loads the entire wordlist into memory. Instead, it processes the input in fixed-size chunks. This approach prevents RAM exhaustion and allows the tool to operate on wordlists that exceed several gigabytes in size. Chunked processing also isolates parsing errors, allowing the tool to skip malformed lines without stopping execution.

<div align="center">
[ Streaming ] ---> [ Chunk Loader ] ---> [ Analyzer ] ---> [ Output Writer ]
</div>

### PyArrow-Backed String Storage
Pandas' PyArrow string backend is used to represent password data. Unlike Python object strings, Arrow arrays store text in contiguous memory blocks, reducing overhead and enabling SIMD-accelerated operations. This choice results in significantly lower memory usage and improved performance for vectorized operations.

### Optimized Entropy Computation
Entropy is computed using vectorized logic. The underlying implementation relies on SciPy's highly optimized C routines, which provide consistent performance even on millions of entries. This avoids Python-level loops, which would otherwise introduce substantial overhead.

### Adaptive Output Strategy
The output format adapts automatically based on dataset size:

- Small datasets are written as ASCII tables for readability.
- Large datasets are exported as CSV files to ensure performance and compatibility with analytical tools.
- Users may request Markdown output for documentation and reporting.

This strategy ensures optimal usability without compromising speed.

<div align="center">
<pre>

Traditional tools:
+---------------------------+
| Load full file            |
| → 1.5 GB in RAM (!)       |
| → crash                   |
+---------------------------+


WordlistRefinery:
+---------------------------+
| Read 100k rows → ~12 MB   |
| Next 100k rows → ~12 MB   |
| ... constant usage        |
+---------------------------+

</pre>
</div>


### Fault-Tolerant Line Parsing
Real-world datasets often contain malformed or non-UTF8 lines. The loader sanitizes and ignores invalid bytes, while preserving all valid passwords. This prevents crashes during long-running operations and ensures that processing can continue uninterrupted.

---

## Examples Directory Explanation

The repository includes an `examples/` directory, which provides ready-to-use sample inputs and outputs. These files demonstrate the behavior of the tool on both small and large datasets.

### small_list.txt
A small demonstration wordlist containing a mix of typical passwords. This file is intended for quick functional tests and for illustrating table output formats.

### small_list_refined.txt
The result of processing `small_list.txt` using the `--add-metadata` option. This file contains an ASCII table including entropy values, complexity flags, and strength classification.

### rockyou_subset_1k.txt
A subset of the first 1,000 lines of the well-known rockyou.txt password dump. This file acts as a realistic example of how the tool behaves on moderately large datasets, without requiring users to load the full corpus.

### rockyou_subset_1k_refined.csv
The processed version of the subset above, generated with metadata enabled. Since the dataset exceeds the ASCII threshold, the output is written as a properly formatted CSV file suitable for spreadsheet software and analytical tools.

### Purpose of these examples
The examples serve multiple purposes:

- Provide a baseline for testing correct installation.
- Demonstrate expected behavior for both small and large inputs.
- Allow continuous integration systems to run tests without accessing extremely large files.
- Serve as reference materials when documenting or presenting the tool.

---

## Testing

WordlistRefinery includes a comprehensive test suite built with `pytest`.  
The tests cover entropy calculation, complexity tagging, WPA2 filtering, the streaming loader, and the command-line interface.

To run the full test suite:

```bash
pytest -q
````

If all tests pass, you should see output similar to:

```
11 passed in 0.23s
```

<img width="979" height="266" alt="image" src="https://github.com/user-attachments/assets/7ed0fc4e-839f-4afa-ba70-d0224dc6360f" />

### Test Layout

The `tests/` directory contains:

* `test_analyzer.py`
  Tests entropy functions, regex filtering, and complexity detection.

* `test_loader.py`
  Ensures correct streaming behavior, chunk generation, and handling of malformed lines.

* `test_cli.py`
  Runs end-to-end CLI tests using Typer's `CliRunner`.

* `conftest.py`
  Contains shared pytest fixtures, including sample dataframes and temporary wordlists.

This structure ensures that each core module is validated independently, and that the entire tool functions correctly when executed through the command line.

---

## Architecture Overview

WordlistRefinery is organized into a modular, maintainable Python package designed for clarity and scalability. The codebase follows the standard `src/` layout, which isolates application logic from project metadata and prevents accidental imports from the working directory.

### Directory Structure

```

wordlist-refinery/
├── src/
│   └── wordlist_refinery/
│       ├── loader.py        # Chunk-based file ingestion engine
│       ├── analyzer.py      # Entropy computation and regex-based filters
│       ├── main.py          # Typer-based CLI orchestrator
│       └── py.typed         # Type checking support (PEP 561)
├── tests/
│   ├── test_analyzer.py     # Unit tests for entropy, filters, regex logic
│   ├── test_loader.py       # Tests for streaming and data parsing
│   ├── test_cli.py          # End-to-end CLI tests
│   └── conftest.py          # Shared pytest fixtures
├── examples/                # Sample input and output datasets
├── pyproject.toml           # Build configuration and dependencies
└── README.md                # Project documentation

````

### Processing Flow

1. **DataLoader**  
   Reads the input file in chunks using PyArrow-backed Pandas, sanitizing malformed lines and keeping RAM usage stable.

2. **PasswordAnalyzer**  
   Processes each chunk, computing entropy, applying filters (WPA2, complexity), and classifying strength metrics.

3. **CLI Orchestrator (main.py)**  
   Streams chunks, applies transformations, displays Rich previews, and writes output as TXT, CSV, or Markdown.

This layered design ensures each component is testable, replaceable, and independently maintainable.

---

## Contributing

Contributions are welcome. To propose changes or add features:

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feature/my-new-feature
    ````

2. Install dependencies:

   ```bash
   pip install -e .
   pip install pytest ruff mypy
   ```
3. Ensure the test suite passes:

   ```bash
   pytest -q
   ```
4. Run code quality tools:

   ```bash
   ruff check .
   mypy src/
   ```
5. Open a pull request with a clear description of the changes.

### Code Style Guidelines

* Follow PEP 8 conventions
* Use type hints (PEP 484)
* Keep functions small and cohesive
* Maintain clear separation between the loader, analyzer, and CLI
* Add or update tests when introducing new features

---

## License

This project is released under the **MIT License**.
You are free to use, modify, and distribute the software, provided that the license file is included in your work.

See the full license text in:

```
LICENSE
```

---

## FAQ

### Why does the tool skip some lines?

Lines containing invalid encoding, extra separators, or binary data are skipped to avoid parser failures. A warning is displayed when this occurs.

### Why does the output format change automatically?

Small datasets use ASCII tables for readability; large datasets default to CSV for performance and compatibility.

### Why is Unicode removed in WPA2 mode?

The WPA2-PSK specification requires ASCII-only passphrases. Unicode passwords are not permitted by the standard.

### Is entropy a perfect measure of password strength?

No. Entropy is a heuristic, but it is effective for distinguishing highly predictable strings from more complex ones.

### Can the tool be used for illegal activity?

Absolutely not. It is intended only for authorized auditing, research, and educational purposes.

---

## Roadmap

Planned and completed features for future releases.

| Feature                                                                | Status        |
| ---------------------------------------------------------------------- | ------------- |
| ASCII chunk preview (Rich table)                                       | **Completed** |
| CSV output for large datasets                                          | **Completed** |
| Markdown table export                                                  | **Completed** |
| GPU-accelerated entropy computation                                    | *Working on*  |
| Parallel processing of chunks (multiprocessing)                        | *Planned*     |
| Advanced statistical analysis (frequency graphs, distribution metrics) | *Planned*     |
| Export to Parquet format                                               | *Planned*     |
| Filter presets for protocols (SSH, RDP, Kerberos, etc.)                | *Planned*     |
| Interactive TUI mode (text user interface)                             | *Planned*     |
| Auto-detection of corrupted or binary-heavy wordlist segments          | *Planned*     |
| Automated benchmarks for dataset sizes                                 | *Planned*     |

---
## Conclusion

What started as a personal exercise became a robust engine for large-scale password analysis. WordlistRefinery is the result of curiosity, discipline, and the desire to build something meaningful  and, of course, it will continue to evolve.
