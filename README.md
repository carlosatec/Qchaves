# Qchaves

Suite de busca de chaves privadas Bitcoin na curva secp256k1.

> [!WARNING]
> **AVISO DE RESPONSABILIDADE E USO ÉTICO**
> Este software foi desenvolvido exclusivamente para fins educacionais e de pesquisa, especificamente para a resolução de desafios criptográficos (Puzzles BTC). O uso desta ferramenta para qualquer atividade ilícita ou sem autorização é estritamente proibido. Os desenvolvedores e contribuidores não se responsabilizam por qualquer uso indevido, perda de dados ou danos decorrentes da utilização do Qchaves.

## Compilação

### Pré-requisitos
```bash
sudo apt update && sudo apt install build-essential libgmp-dev -y
```

### Compilar tudo
```bash
make all -j$(nproc)
```

### Compilar individualmente
```bash
make address   # Compila modo-address
make bsgs      # Compila modo-bsgs
make kangaroo  # Compila modo-kangaroo
```

---

## Módulos Disponíveis

### 1. Address (modo-address)

Busca chaves privadas comparando endereços gerados com uma lista de endereços-alvo.

**Quando usar:**
- Você tem uma lista de endereços Bitcoin para buscar
- Range pequeno a médio (puzzles até ~80)
- Busca sequencial ou aleatória

**Parâmetros principais:**
- `-f` - Arquivo com os endereços-alvo (formato: 1... ou pubkey hex)
- `-b` - Bit range (ex: 66 = busca entre 2^65 e 2^66)
- `-t` - Número de threads
- `-R` - Modo de busca (sequential, backward, both, random, dance)
- `-l` - Tipo de busca: compress, uncompress, both
- `-A` - Auto-tuning (safe, balanced, max)

**Exemplos:**
```bash
# Busca aleatória em puzzle 21
./Address/modo-address -f Puzzles/21.txt -b 21 -l compress -R -t 8

# Busca sequencial
./Address/modo-address -f Puzzles/21.txt -b 21 -l compress -t 8

# Auto-tuning (recomendado)
./Address/modo-address -A balanced -f Puzzles/21.txt -b 21 -R
```

---

### 2. BSGS (modo-bsgs)

Baby-Step Giant-Step. Algoritmo rápido para ranges conhecidos, mas requer muita RAM.

**Quando usar:**
- Range médio a grande (puzzles 32-80)
- Você tem RAM suficiente (mínimo 4GB, ideal 16GB+)
- Conhece o intervalo exato da chave

**Modos de busca:**
- `-R sequential` - Do início ao fim (padrão)
- `-R backward` - Do fim para o início
- `-R both` - Metade das threads para cada lado (mais rápido)
- `-R random` - Posições aleatórias (puzzles)
- `-R dance` - Mix aleatório de todos modos

**Parâmetros principais:**
- `-f` - Arquivo com as public keys-alvo
- `-b` - Bit range
- `-t` - Número de threads
- `-k` - Fator de memória (quanto maior = mais rápido, mais RAM)
- `-n` - Tamanho da tabela BSGS
- `-A` - Auto-tuning (safe, balanced, max)

**Exemplos:**
```bash
# BSGS normal com 8 threads
./BSGS/modo-bsgs -f Puzzles/66.txt -b 66 -t 8

# BSGS modo random (para puzzles)
./BSGS/modo-bsgs -R random -f Puzzles/66.txt -b 66 -t 8

# Com mais RAM (k=32)
./BSGS/modo-bsgs -f Puzzles/66.txt -b 66 -k 32 -t 16

# Auto-tuning
./BSGS/modo-bsgs -A balanced -f Puzzles/66.txt -b 66
```

**Guia de RAM:**
- 4GB RAM -> -k 512
- 8GB RAM -> -k 1024
- 16GB RAM -> -k 2048
- 32GB RAM -> -k 4096
- 64GB+ RAM -> -k 8192

---

### 3. Kangaroo (modo-kangaroo)

Pollard's Kangaroo. Melhor para ranges gigantes onde BSGS seria impossível (puzzles 100+).

**Quando usar:**
- Range muito grande (puzzles 100+)
- Não tem RAM suficiente para BSGS
- Busca em intervalos conhecidos

**Parâmetros principais:**
- `-p` - Public key alvo em hex
- `-r` - Range em hex (ex: 0:FFFFFFFFFFFFFFFF)
- `-b` - ID do puzzle (para nome do checkpoint)
- `-t` - Número de threads
- `-d` - Bits para distinguished points (20-23)
- `-m` - Limite de RAM em GB para tabela de traps
- `-j` - Número de saltos ativos
- `-w` - Número de kangaroos wild na frota
- `-A` Auto-tuning (safe, balanced, max)

**Exemplos:**
```bash
# Kangaroo normal
./kangaroo/modo-kangaroo -p 02ABCD... -b 130 -r 0:FFFFFFFFFFFFFFFF -t 12 -d 22 -j 48 -w 40

# Auto-tuning (recomendado)
./kangaroo/modo-kangaroo -A balanced -p 02ABCD... -b 130 -r 0:FFFFFFFFFFFFFFFF
```

---

## Checkpoints

Todos os módulos salvam checkpoints automaticamente:

- **A cada 5 minutos** (auto-save)
- **Ao pressionar Ctrl+C** (salvamento de emergência)

**Arquivos de checkpoint:**
- `address_bitXX.ckp` (XX = bit range)
- `bsgs_bitXX.ckp`
- `kangaroo_bitXX.ckp`

**Retomar busca:**
- Os módulos pedem confirmação ao detectar checkpoint
- Ou use variável de ambiente: `QCHAVES_AUTO_RESUME=1` (auto-retomar) / `=0` (ignorar)

---

## Parâmetros Gerais

| Parâmetro | Descrição |
|-----------|-----------|
| `-t` | Threads (use o número de núcleos da CPU) |
| `-s` | Intervalo de stats em segundos |
| `-d` | Ativar modo debug |
| `-q` | Modo silencioso |
| `-A` | Auto-tuning (safe/balanced/max) |

---

## Auto-Tuning

O auto-tuning detecta seu hardware e ajusta os parâmetros automaticamente.

**Perfis:**
- `safe` - (metade dos recursos)
- `balanced` - equilíbrio (recomendado)
- `max` - agressivo (todos os recursos)

**O que é detectado:**
- Número de threads
- RAM total e disponível
- Ambiente WSL/Windows/Linux
- Perfil de hardware

**Exemplo com overrides:**
```bash
# Usa perfil max, mas força apenas 8 threads
./BSGS/modo-bsgs -A max -t 8 -f Puzzles/66.txt -b 66
```

---

## Resultados

Ao encontrar uma chave, o programa exibe:
- Chave privada (hex e decimal)
- Endereço Bitcoin
- WIF (pronto para importar no Electrum/BlueWallet)
- Puzzle ID

As chaves são salvas em `FOUND_KEYS.txt`.

---

## Notas Importantes

1. **Sem Swap**: O programa não funciona bem com Swap. Use apenas RAM física.

2. **Performance**: Sempre use `-t` com o número de núcleos da CPU.

3. **Puzzles**: Os arquivos em `Puzzles/` contém os alvos para cada puzzle.

---

## Créditos

Este projeto é uma derivação e integração de ferramentas de alto desempenho da comunidade de criptografia:

- **[Keyhunt](https://github.com/albertobsd/keyhunt)**: Originalmente desenvolvido por **AlbertoBSD**. O motor principal de busca e os algoritmos de Baby-step Giant-step são baseados em seu trabalho excepcional.
- **[Cacachave](https://github.com/lmajowka/cacachave)**: Versão adaptada por **lmajowka**, que serviu como base para a interface e localização inicial deste projeto.

Agradecimentos especiais à comunidade de criptografia por compartilhar ferramentas de código aberto de alta performance.