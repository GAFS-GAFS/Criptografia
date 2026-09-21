#!/usr/bin/env bash

set -euo pipefail

CALL_DIRECTORY=$(pwd)
PROJECT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_INPUT="$PROJECT_DIRECTORY/data/original/exemplo.txt"

usage() {
    cat <<'EOF'
Uso simplificado:
  ./securebridge.sh --affine <chave> [arquivo]
  ./securebridge.sh --aes <chave> [arquivo]
  ./securebridge.sh --rsa [arquivo]
  ./securebridge.sh --all <chave> [arquivo]

Outros comandos:
  ./securebridge.sh --keygen-rsa
  ./securebridge.sh --test
  ./securebridge.sh --benchmark [repeticoes] [chave]
  ./securebridge.sh --clean
  ./securebridge.sh --clean-build
  ./securebridge.sh --clean-all
  ./securebridge.sh --help

Se o arquivo for omitido, sera usado data/original/exemplo.txt.
As opcoes nao diferenciam maiusculas e minusculas.
EOF
}

resolve_input() {
    local supplied_path=${1:-}

    if [[ -z "$supplied_path" ]]; then
        printf '%s\n' "$DEFAULT_INPUT"
    elif [[ "$supplied_path" = /* ]]; then
        printf '%s\n' "$supplied_path"
    else
        printf '%s/%s\n' "$CALL_DIRECTORY" "$supplied_path"
    fi
}

prepare_input() {
    local input_path=$1
    if [[ ! -f "$input_path" ]]; then
        printf 'Erro: arquivo de entrada nao encontrado: %s\n' "$input_path" >&2
        exit 2
    fi
}

file_stem() {
    local filename
    filename=$(basename -- "$1")
    printf '%s\n' "${filename%.*}"
}

file_extension() {
    local filename
    filename=$(basename -- "$1")
    if [[ "$filename" == *.* ]]; then
        printf '.%s\n' "${filename##*.}"
    else
        printf '%s\n' '.txt'
    fi
}

build_project() {
    make -s
    mkdir -p data/encrypted data/recovered results
}

prepare_benchmark_environment() {
    local venv_directory="$PROJECT_DIRECTORY/.venv"
    BENCHMARK_PYTHON="$venv_directory/bin/python3"

    if [[ ! -x "$BENCHMARK_PYTHON" ]]; then
        if ! command -v python3 >/dev/null 2>&1; then
            printf '%s\n' 'Erro: Python 3 nao foi encontrado.' >&2
            exit 2
        fi

        printf '%s\n' 'Ambiente virtual ausente; criando .venv...'
        if ! python3 -m venv --system-site-packages "$venv_directory"; then
            printf '%s\n' \
                'Erro: nao foi possivel criar a venv. Instale o pacote python3-venv.' >&2
            exit 2
        fi
    fi

    if ! "$BENCHMARK_PYTHON" -c 'import matplotlib' >/dev/null 2>&1; then
        if [[ ! -f "$PROJECT_DIRECTORY/requirements.txt" ]]; then
            printf 'Erro: arquivo de dependencias nao encontrado: %s\n' \
                "$PROJECT_DIRECTORY/requirements.txt" >&2
            exit 2
        fi

        printf '%s\n' 'Instalando as dependencias do benchmark na .venv...'
        "$BENCHMARK_PYTHON" -m pip install \
            -r "$PROJECT_DIRECTORY/requirements.txt"
    fi
}

run_symmetric() {
    local algorithm=$1
    local passphrase=$2
    local input_path=$3
    local stem extension encrypted_path recovered_path

    stem=$(file_stem "$input_path")
    extension=$(file_extension "$input_path")

    if [[ "$algorithm" == "affinetrans" ]]; then
        encrypted_path="data/encrypted/${stem}.sbr"
        recovered_path="data/recovered/${stem}-affinetrans${extension}"
    else
        encrypted_path="data/encrypted/${stem}.aes"
        recovered_path="data/recovered/${stem}-aes${extension}"
    fi

    ./securebridge simulate "$algorithm" \
        "$input_path" "$encrypted_path" "$recovered_path" \
        --key "$passphrase"
}

ensure_rsa_keys() {
    mkdir -p keys

    if [[ ! -f keys/private.pem && ! -f keys/public.pem ]]; then
        printf 'Chaves RSA ausentes; gerando um par RSA-2048 para a demonstracao.\n'
        ./securebridge keygen-rsa keys/private.pem keys/public.pem
    elif [[ ! -f keys/private.pem || ! -f keys/public.pem ]]; then
        printf '%s\n' \
            'Erro: existe apenas uma das chaves RSA. Gere novamente um par completo.' >&2
        exit 2
    fi
}

run_rsa() {
    local input_path=$1
    local stem extension encrypted_path recovered_path

    ensure_rsa_keys
    stem=$(file_stem "$input_path")
    extension=$(file_extension "$input_path")
    encrypted_path="data/encrypted/${stem}.rsa"
    recovered_path="data/recovered/${stem}-rsa${extension}"

    ./securebridge simulate rsa \
        "$input_path" "$encrypted_path" "$recovered_path" \
        --public keys/public.pem --private keys/private.pem
}

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

OPTION=${1,,}
shift
cd "$PROJECT_DIRECTORY"

case "$OPTION" in
    --affine)
        [[ $# -ge 1 && $# -le 2 ]] || { usage; exit 1; }
        PASSPHRASE=$1
        INPUT=$(resolve_input "${2:-}")
        prepare_input "$INPUT"
        build_project
        run_symmetric affinetrans "$PASSPHRASE" "$INPUT"
        ;;
    --aes)
        [[ $# -ge 1 && $# -le 2 ]] || { usage; exit 1; }
        PASSPHRASE=$1
        INPUT=$(resolve_input "${2:-}")
        prepare_input "$INPUT"
        build_project
        run_symmetric aes "$PASSPHRASE" "$INPUT"
        ;;
    --rsa)
        [[ $# -le 1 ]] || { usage; exit 1; }
        INPUT=$(resolve_input "${1:-}")
        prepare_input "$INPUT"
        build_project
        run_rsa "$INPUT"
        ;;
    --all)
        [[ $# -ge 1 && $# -le 2 ]] || { usage; exit 1; }
        PASSPHRASE=$1
        INPUT=$(resolve_input "${2:-}")
        prepare_input "$INPUT"
        build_project
        run_symmetric affinetrans "$PASSPHRASE" "$INPUT"
        run_symmetric aes "$PASSPHRASE" "$INPUT"
        run_rsa "$INPUT"
        ;;
    --keygen-rsa)
        [[ $# -eq 0 ]] || { usage; exit 1; }
        build_project
        mkdir -p keys
        ./securebridge keygen-rsa keys/private.pem keys/public.pem
        ;;
    --test)
        [[ $# -eq 0 ]] || { usage; exit 1; }
        make test
        ;;
    --benchmark)
        [[ $# -le 2 ]] || { usage; exit 1; }
        ITERATIONS=${1:-30}
        [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] || {
            printf '%s\n' 'Erro: repeticoes deve ser um numero inteiro maior que zero.' >&2
            exit 2
        }

        PASSPHRASE=${2:-}
        if [[ -z "$PASSPHRASE" ]]; then
            printf '%s' 'Digite a chave do benchmark: ' >&2
            if ! IFS= read -r -s PASSPHRASE; then
                printf '\n%s\n' 'Erro: nao foi possivel ler a chave.' >&2
                exit 2
            fi
            printf '\n' >&2
        fi
        if [[ -z "$PASSPHRASE" ]]; then
            printf '%s\n' 'Erro: a chave do benchmark nao pode ser vazia.' >&2
            exit 2
        fi

        build_project
        prepare_benchmark_environment
        "$BENCHMARK_PYTHON" scripts/benchmark.py \
            --iterations "$ITERATIONS" \
            --key "$PASSPHRASE"
        ;;
    --clean)
        [[ $# -eq 0 ]] || { usage; exit 1; }
        make clean-generated
        ;;
    --clean-build)
        [[ $# -eq 0 ]] || { usage; exit 1; }
        make clean
        ;;
    --clean-all)
        [[ $# -eq 0 ]] || { usage; exit 1; }
        make clean-all
        ;;
    --help|-h)
        usage
        ;;
    *)
        printf 'Erro: opcao desconhecida: %s\n\n' "$OPTION" >&2
        usage
        exit 1
        ;;
esac
