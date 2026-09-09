# SecureBridge — C++17 e OpenSSL

Aplicação acadêmica que simula a transmissão segura de documentos entre um sistema interno e um SAP simulado.

Algoritmos disponíveis:

- **AffineTrans:** cifra criada para o trabalho, combinando permutação afim de bytes e transposição em blocos;
- **AES-256-GCM:** implementação autenticada pela interface EVP da OpenSSL;
- **RSA-2048-OAEP-SHA256:** cifragem direta em blocos para o experimento acadêmico.

> A AffineTrans não deve proteger dados reais. A cifragem direta de arquivos com RSA também não é a prática usada em produção; sistemas reais normalmente usam AES para os dados e RSA para proteger a chave AES.

## Dependências

No Ubuntu, Debian ou Linux Mint:

```bash
sudo apt update
sudo apt install g++ make libssl-dev
```

O projeto precisa de:

- Compilador compatível com C++17;
- GNU Make;
- Cabeçalhos e biblioteca de desenvolvimento da OpenSSL.

## Compilação e testes

```bash
make
make test
```

Também existe um atalho:

```bash
./securebridge.sh --test
```

Os testes cobrem:

- Diferentes tamanhos, incluindo arquivos vazios;
- Limites dos blocos AffineTrans e RSA;
- Recuperação byte a byte nos três algoritmos;
- Detecção de alteração pelo AES-GCM;
- Rejeição de bloco RSA-OAEP alterado.

## AffineTrans

### Cifrar

```bash
./securebridge encrypt affinetrans \
  data/original/exemplo.txt \
  data/encrypted/exemplo.sbr \
  --key "minha-chave"
```

### Decifrar

```bash
./securebridge decrypt affinetrans \
  data/encrypted/exemplo.sbr \
  data/recovered/exemplo.txt \
  --key "minha-chave"
```

### Simular

```bash
./securebridge simulate affinetrans \
  data/original/exemplo.txt \
  data/encrypted/exemplo.sbr \
  data/recovered/exemplo.txt \
  --key "minha-chave"
```

Atalho equivalente, usando o arquivo de exemplo quando nenhum caminho for informado:

```bash
./securebridge.sh --affine "NeymarJr"
```

## AES-256-GCM

A frase-chave é transformada em uma chave de 256 bits por SHA-256. Cada cifragem gera um nonce aleatório de 96 bits e uma tag de autenticação de 128 bits.

### Cifrar e decifrar

```bash
./securebridge encrypt aes \
  data/original/exemplo.txt \
  data/encrypted/exemplo.aes \
  --key "minha-chave"

./securebridge decrypt aes \
  data/encrypted/exemplo.aes \
  data/recovered/exemplo-aes.txt \
  --key "minha-chave"
```

### Simular

```bash
./securebridge simulate aes \
  data/original/exemplo.txt \
  data/encrypted/exemplo.aes \
  data/recovered/exemplo-aes.txt \
  --key "minha-chave"
```

Atalho:

```bash
./securebridge.sh --aes "NeymarJr"
```

Se a chave estiver incorreta ou o arquivo for alterado, a autenticação GCM falhará.

## RSA-OAEP

### Gerar o par de chaves

```bash
./securebridge keygen-rsa \
  keys/private.pem \
  keys/public.pem
```

A chave privada gerada não possui senha e não deve ser publicada ou enviada ao Git. Ela existe somente para a demonstração acadêmica.

### Cifrar e decifrar

```bash
./securebridge encrypt rsa \
  data/original/exemplo.txt \
  data/encrypted/exemplo.rsa \
  --key keys/public.pem

./securebridge decrypt rsa \
  data/encrypted/exemplo.rsa \
  data/recovered/exemplo-rsa.txt \
  --key keys/private.pem
```

### Simular

```bash
./securebridge simulate rsa \
  data/original/exemplo.txt \
  data/encrypted/exemplo.rsa \
  data/recovered/exemplo-rsa.txt \
  --public keys/public.pem \
  --private keys/private.pem
```

Atalho: se nenhuma chave existir, o script gera automaticamente um par RSA-2048 em `keys/`.

```bash
./securebridge.sh --rsa
```

Para executar os três algoritmos em sequência:

```bash
./securebridge.sh --all "NeymarJr"
```

Um arquivo diferente pode ser informado como último argumento:

```bash
./securebridge.sh --all "NeymarJr" data/original/alice_50KiB.txt
```

Com RSA de 2048 bits e OAEP/SHA-256, cada bloco aceita no máximo 190 bytes e produz 256 bytes cifrados. O programa divide e remonta os arquivos automaticamente.

## Saída da simulação

A simulação exibe:

- Algoritmo e tamanho do arquivo;
- Amostra hexadecimal do conteúdo interceptado;
- Tempo isolado de cifragem;
- Tempo isolado de decifragem;
- SHA-256 original e recuperado;
- Resultado da comparação byte a byte.

Leitura, escrita, carregamento ou derivação de chaves e cálculo dos hashes não são incluídos nos tempos exibidos.

## Limpeza

Os arquivos originais e as chaves RSA nunca são removidos pelos comandos abaixo.

```bash
# Remove somente os arquivos gerados em data/encrypted,
# data/recovered e results.
make clean-generated

# Remove somente binários e objetos da compilação.
make clean

# Executa as duas limpezas anteriores.
make clean-all

# Alias em português para make clean-all.
make limpar
```

O script também oferece atalhos:

```bash
./securebridge.sh --clean
./securebridge.sh --clean-build
./securebridge.sh --clean-all
```

## Estrutura

```text
securebridge/
├── include/
│   ├── aes_cipher.hpp
│   ├── affinetrans.hpp
│   ├── file_utils.hpp
│   ├── openssl_utils.hpp
│   ├── rsa_cipher.hpp
│   ├── sha256.hpp
│   └── types.hpp
├── src/
├── tests/
├── data/
│   ├── original/
│   ├── encrypted/
│   └── recovered/
├── results/
├── Makefile
└── README.md
```

## Próximas etapas

- Preparar os quatro arquivos de texto do Projeto Gutenberg;
- Implementar benchmark com múltiplas repetições;
- Exportar média, mediana e demais resultados para CSV;
- Gerar os gráficos de cifragem e decifragem;
- Produzir o relatório final.
