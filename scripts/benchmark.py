#!/usr/bin/env python3
"""Executa benchmarks repetidos do SecureBridge e gera CSVs e graficos."""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import re
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


PROJECT_DIR = Path(__file__).resolve().parent.parent
BINARY = PROJECT_DIR / "securebridge"
DEFAULT_INPUT_DIR = PROJECT_DIR / "data" / "original"
DEFAULT_OUTPUT_DIR = PROJECT_DIR / "results"
PRIVATE_KEY = PROJECT_DIR / "keys" / "private.pem"
PUBLIC_KEY = PROJECT_DIR / "keys" / "public.pem"
TIME_PATTERN = re.compile(r"^Tempo:\s+([0-9]+(?:[.,][0-9]+)?)\s+ms$", re.MULTILINE)

ALGORITHMS = ("affinetrans", "aes", "rsa")
ALGORITHM_LABELS = {
    "affinetrans": "AffineTrans",
    "aes": "AES-256-GCM",
    "rsa": "RSA-2048-OAEP",
}
OPERATION_LABELS = {
    "cifragem": "Cifragem",
    "decifragem": "Decifragem",
}


@dataclass(frozen=True)
class Sample:
    algorithm: str
    input_path: Path
    size_bytes: int
    size_range: str
    operation: str
    iteration: int
    time_ms: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Executa AffineTrans, AES e RSA varias vezes, verifica os arquivos "
            "recuperados e gera CSVs e graficos."
        )
    )
    parser.add_argument(
        "--inputs",
        nargs="+",
        type=Path,
        help="Arquivos de entrada. Sem esta opcao, usa todos os .txt de data/original.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=30,
        help="Numero de medicoes por algoritmo e arquivo (padrao: 30).",
    )
    parser.add_argument(
        "--warmups",
        type=int,
        default=2,
        help="Numero de aquecimentos nao registrados (padrao: 2).",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Frase-chave escolhida pelo usuario para AffineTrans e AES.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Diretorio dos CSVs e graficos (padrao: results).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=2026,
        help="Semente da ordem aleatoria das execucoes (padrao: 2026).",
    )
    parser.add_argument(
        "--allow-incomplete-ranges",
        action="store_true",
        help="Permite executar sem que as quatro faixas do trabalho estejam presentes.",
    )
    return parser.parse_args()


def size_range(size_bytes: int) -> str:
    if size_bytes < 1024:
        return "< 1 KB"
    if size_bytes < 10 * 1024:
        return "1 a < 10 KB"
    if size_bytes <= 100 * 1024:
        return "10 a 100 KB"
    return "> 100 KB"


def discover_inputs(paths: Optional[Sequence[Path]]) -> List[Path]:
    if paths:
        candidates = list(paths)
    else:
        candidates = sorted(DEFAULT_INPUT_DIR.glob("*.txt"))

    resolved: List[Path] = []
    for path in candidates:
        absolute = path if path.is_absolute() else (Path.cwd() / path)
        absolute = absolute.resolve()
        if not absolute.is_file():
            raise ValueError(f"Arquivo de entrada nao encontrado: {path}")
        resolved.append(absolute)

    if not resolved:
        raise ValueError("Nenhum arquivo .txt foi encontrado para o benchmark")
    return sorted(set(resolved), key=lambda item: (item.stat().st_size, item.name))


def validate_ranges(inputs: Sequence[Path], allow_incomplete: bool) -> None:
    expected = {"< 1 KB", "1 a < 10 KB", "10 a 100 KB", "> 100 KB"}
    present = {size_range(path.stat().st_size) for path in inputs}
    missing = sorted(expected - present)
    if missing and not allow_incomplete:
        formatted = ", ".join(missing)
        raise ValueError(
            "Faltam arquivos nas faixas: "
            f"{formatted}. Adicione os textos ou use --allow-incomplete-ranges."
        )


def run_command(arguments: Sequence[str]) -> str:
    result = subprocess.run(
        arguments,
        cwd=PROJECT_DIR,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        command = " ".join(arguments)
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Comando falhou ({command}):\n{details}")
    return result.stdout


def extract_time(output: str) -> float:
    match = TIME_PATTERN.search(output)
    if not match:
        raise RuntimeError(f"Nao foi possivel localizar o tempo na saida:\n{output}")
    return float(match.group(1).replace(",", "."))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_binary_and_keys() -> None:
    run_command(["make", "-s"])
    PRIVATE_KEY.parent.mkdir(parents=True, exist_ok=True)

    if not PRIVATE_KEY.exists() and not PUBLIC_KEY.exists():
        run_command(
            [str(BINARY), "keygen-rsa", str(PRIVATE_KEY), str(PUBLIC_KEY)]
        )
    elif not PRIVATE_KEY.exists() or not PUBLIC_KEY.exists():
        raise ValueError(
            "Existe apenas uma chave RSA. Remova o arquivo restante ou gere um par completo."
        )


def key_for(algorithm: str, operation: str, passphrase: str) -> str:
    if algorithm != "rsa":
        return passphrase
    return str(PUBLIC_KEY if operation == "encrypt" else PRIVATE_KEY)


def run_pair(
    algorithm: str,
    input_path: Path,
    passphrase: str,
    temporary_dir: Path,
) -> Tuple[float, float]:
    token = hashlib.sha256(str(input_path).encode("utf-8")).hexdigest()[:12]
    encrypted = temporary_dir / f"{token}-{algorithm}.encrypted"
    recovered = temporary_dir / f"{token}-{algorithm}.recovered"

    encryption_output = run_command(
        [
            str(BINARY),
            "encrypt",
            algorithm,
            str(input_path),
            str(encrypted),
            "--key",
            key_for(algorithm, "encrypt", passphrase),
        ]
    )
    decryption_output = run_command(
        [
            str(BINARY),
            "decrypt",
            algorithm,
            str(encrypted),
            str(recovered),
            "--key",
            key_for(algorithm, "decrypt", passphrase),
        ]
    )

    if sha256_file(input_path) != sha256_file(recovered):
        raise RuntimeError(
            f"Falha de integridade em {ALGORITHM_LABELS[algorithm]} / {input_path.name}"
        )

    return extract_time(encryption_output), extract_time(decryption_output)


def print_inputs(inputs: Sequence[Path]) -> None:
    print("Arquivos selecionados:")
    for path in inputs:
        size = path.stat().st_size
        print(f"  - {path.name}: {size} bytes ({size_range(size)})")


def execute_benchmark(args: argparse.Namespace, inputs: Sequence[Path]) -> List[Sample]:
    combinations = [(algorithm, path) for path in inputs for algorithm in ALGORITHMS]
    generator = random.Random(args.seed)
    samples: List[Sample] = []
    total = args.iterations * len(combinations)
    completed = 0

    with tempfile.TemporaryDirectory(prefix="securebridge-benchmark-") as temp:
        temporary_dir = Path(temp)

        if args.warmups:
            print(f"Aquecimento: {args.warmups} rodada(s), sem registrar tempos...")
        for _ in range(args.warmups):
            warmup_order = combinations.copy()
            generator.shuffle(warmup_order)
            for algorithm, input_path in warmup_order:
                run_pair(algorithm, input_path, args.key, temporary_dir)

        print(f"Medicao: {args.iterations} rodada(s) por combinacao...")
        for iteration in range(1, args.iterations + 1):
            current_order = combinations.copy()
            generator.shuffle(current_order)
            for algorithm, input_path in current_order:
                encryption_ms, decryption_ms = run_pair(
                    algorithm, input_path, args.key, temporary_dir
                )
                size = input_path.stat().st_size
                common = {
                    "algorithm": algorithm,
                    "input_path": input_path,
                    "size_bytes": size,
                    "size_range": size_range(size),
                    "iteration": iteration,
                }
                samples.append(
                    Sample(operation="cifragem", time_ms=encryption_ms, **common)
                )
                samples.append(
                    Sample(operation="decifragem", time_ms=decryption_ms, **common)
                )
                completed += 1
                print(
                    f"\r  Progresso: {completed}/{total} combinacoes",
                    end="",
                    flush=True,
                )
    print()
    return samples


def write_raw_csv(samples: Sequence[Sample], output_path: Path) -> None:
    fields = [
        "algoritmo",
        "arquivo",
        "faixa",
        "tamanho_bytes",
        "operacao",
        "repeticao",
        "tempo_ms",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for sample in samples:
            writer.writerow(
                {
                    "algoritmo": ALGORITHM_LABELS[sample.algorithm],
                    "arquivo": sample.input_path.name,
                    "faixa": sample.size_range,
                    "tamanho_bytes": sample.size_bytes,
                    "operacao": OPERATION_LABELS[sample.operation],
                    "repeticao": sample.iteration,
                    "tempo_ms": f"{sample.time_ms:.6f}",
                }
            )


SummaryKey = Tuple[str, Path, int, str, str]


def summarize(samples: Sequence[Sample]) -> List[Dict[str, object]]:
    groups: Dict[SummaryKey, List[float]] = defaultdict(list)
    for sample in samples:
        key = (
            sample.algorithm,
            sample.input_path,
            sample.size_bytes,
            sample.size_range,
            sample.operation,
        )
        groups[key].append(sample.time_ms)

    operation_order = {"cifragem": 0, "decifragem": 1}
    rows: List[Dict[str, object]] = []
    for key, values in sorted(
        groups.items(),
        key=lambda item: (
            item[0][2],
            ALGORITHMS.index(item[0][0]),
            operation_order[item[0][4]],
        ),
    ):
        algorithm, path, size, current_range, operation = key
        rows.append(
            {
                "algoritmo": ALGORITHM_LABELS[algorithm],
                "arquivo": path.name,
                "faixa": current_range,
                "tamanho_bytes": size,
                "operacao": OPERATION_LABELS[operation],
                "amostras": len(values),
                "media_ms": statistics.fmean(values),
                "mediana_ms": statistics.median(values),
                "desvio_padrao_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
                "minimo_ms": min(values),
                "maximo_ms": max(values),
            }
        )
    return rows


def write_summary_csv(rows: Sequence[Dict[str, object]], output_path: Path) -> None:
    fields = [
        "algoritmo",
        "arquivo",
        "faixa",
        "tamanho_bytes",
        "operacao",
        "amostras",
        "media_ms",
        "mediana_ms",
        "desvio_padrao_ms",
        "minimo_ms",
        "maximo_ms",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            formatted = dict(row)
            for field in (
                "media_ms",
                "mediana_ms",
                "desvio_padrao_ms",
                "minimo_ms",
                "maximo_ms",
            ):
                formatted[field] = f"{float(row[field]):.6f}"
            writer.writerow(formatted)


def import_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise RuntimeError(
            "O matplotlib nao esta instalado. Execute o benchmark pelo "
            "securebridge.sh para preparar a .venv automaticamente."
        ) from error
    return plt


def create_chart(
    rows: Sequence[Dict[str, object]],
    operation: str,
    output_path: Path,
) -> None:
    plt = import_matplotlib()
    selected = [row for row in rows if row["operacao"] == OPERATION_LABELS[operation]]
    files = sorted(
        {(int(row["tamanho_bytes"]), str(row["arquivo"]), str(row["faixa"])) for row in selected}
    )
    x_positions = list(range(len(files)))
    tick_labels = [f"{current_range}\n{size} B" for size, _, current_range in files]

    figure, axis = plt.subplots(figsize=(10, 6))
    all_values: List[float] = []
    for algorithm in ALGORITHMS:
        label = ALGORITHM_LABELS[algorithm]
        values_by_file = {
            (int(row["tamanho_bytes"]), str(row["arquivo"]), str(row["faixa"])): float(
                row["mediana_ms"]
            )
            for row in selected
            if row["algoritmo"] == label
        }
        values = [values_by_file.get(file_key, float("nan")) for file_key in files]
        all_values.extend(value for value in values if value > 0)
        axis.plot(x_positions, values, marker="o", linewidth=2, label=label)

    if all_values:
        axis.set_yscale("log")
    axis.set_xticks(x_positions, tick_labels)
    axis.set_xlabel("Faixa e tamanho do arquivo")
    axis.set_ylabel("Tempo mediano (ms) — escala logaritmica")
    axis.set_title(f"SecureBridge — tempo de {operation}")
    axis.grid(True, which="both", linestyle="--", alpha=0.35)
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=180)
    plt.close(figure)


def main() -> int:
    args = parse_args()
    try:
        if args.iterations < 1:
            raise ValueError("--iterations deve ser maior que zero")
        if args.warmups < 0:
            raise ValueError("--warmups nao pode ser negativo")

        inputs = discover_inputs(args.inputs)
        validate_ranges(inputs, args.allow_incomplete_ranges)
        print_inputs(inputs)
        import_matplotlib()
        ensure_binary_and_keys()

        samples = execute_benchmark(args, inputs)
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        raw_csv = output_dir / "benchmark_detalhado.csv"
        summary_csv = output_dir / "benchmark_resumo.csv"
        encryption_chart = output_dir / "grafico_cifragem.png"
        decryption_chart = output_dir / "grafico_decifragem.png"

        write_raw_csv(samples, raw_csv)
        rows = summarize(samples)
        write_summary_csv(rows, summary_csv)
        create_chart(rows, "cifragem", encryption_chart)
        create_chart(rows, "decifragem", decryption_chart)

        print("Resultados gerados:")
        for path in (raw_csv, summary_csv, encryption_chart, decryption_chart):
            print(f"  - {path}")
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
