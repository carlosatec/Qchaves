# 🚀 Qchaves Core Engines: Suite de Módulos de Alta Performance

Bem-vindo à nova arquitetura modular do **Qchaves**. Este diretório contém os motores de busca core, cada um otimizado para cenários específicos de recuperação de chaves privadas na curva elíptica `secp256k1`.

---

## 🛠️ Como Compilar

A estrutura agora utiliza um sistema de compilação unificado. Certifique-se de estar em um ambiente **WSL (Debian/Ubuntu)** ou **Linux**.

### 1. Pré-requisitos
Instale as dependências essenciais:
```bash
sudo apt update && sudo apt install build-essential libgmp-dev -y
```

### 2. Compilação Global (Recomendado)
Para compilar todos os módulos de uma vez e gerar os binários otimizados:
```bash
make all -j$(nproc)

make clean all  // para limpar os arquivos gerados

```

### 3. Compilação Individual
Você também pode compilar módulos específicos caso precise de apenas um:
```bash
make address   # Compila apenas o modo-address
make bsgs      # Compila apenas o modo-bsgs
make kangaroo  # Compila apenas o modo-kangaroo
```

---

## 🏎️ Resumo dos Módulos e Exemplos de Uso

Cada módulo gera um binário independente padronizado com o prefixo `modo-`. Para rodar os exemplos abaixo, certifique-se de estar dentro da pasta `Modulos/`.

### 📍 1. Address Engine (`modo-address`)
O motor de busca por endereços clássico, agora refatorado para performance extrema (**v2.1**).
- **Busca Incremental:** Otimizado com `startP` incremental (+20-40% de boost), eliminando multiplicações escalares redundantes.
- **Fused Hot Loop:** Lógica de hashing e verificação fundida em um único ciclo, minimizando *branch mispredictions*.
- **Checkpoint Revisado:** O formato atual salva cursor, `range_end` e modo randômico com compatibilidade legada.
- **Correções Estruturais:** Remoção de UB em vetores BSGS internos, correções de concorrência em `steps/ends` e cleanup de workers.
- **Hot Path BTC Melhorado:** Caminho comum `BTC + !endomorphism` foi simplificado para reduzir branches por batch.
- **RNG por Thread:** Randômico agora usa estado independente por thread (`thread_rand()`) para melhor reprodução e performance.
- **Auto-Tuning V1**: Suporta `--auto`, `--auto=safe`, `--auto=balanced`, `--auto=max` e `--auto=benchmark`, detectando threads, RAM e WSL para sugerir `-t`.
- **Uso ideal:** Quando você tem uma lista de endereços Bitcoin (1...) e quer testar grandes intervalos sequenciais ou randômicos.
- **Exemplo (Puzzle 21):**
  ```bash
  ./Address/modo-address -f Puzzles/21.txt -b 21 -l compress -t 8 -s 10
  ```
  ```bash
  ./Address/modo-address --auto=balanced -f Puzzles/21.txt -b 21
  ```

### 👶 2. BSGS Engine (`modo-bsgs`)
Implementação do algoritmo *Baby-step Giant-step*.
- **Checkpoint v3:** Formato atual salva range, progresso, modo BSGS e estado `bsgs_found` para múltiplos alvos, com compatibilidade retroativa (BSGS/BSGS2/BSGS3).
- **Validação Final Endurecida:** A confirmação final passou a comparar o ponto completo, não apenas `x`.
- **Workers Mais Seguros:** Melhorias de concorrência em `steps/ends`, `bsgs_found` com visibilidade mais consistente e RNG local por thread nos modos randômicos.
- **RNG por Thread:** Modos randômicos agora usam `thread_rng_next_bounded()` com estado independente por thread.
- **Hot Path Otimizado:** secondcheck/thirdcheck agora reaproveitam pontos pré-computados do loop principal, eliminando `ComputePublicKey()` redundante.
- **Auto-Tuning V1**: Suporta `--auto`, `--auto=safe`, `--auto=balanced`, `--auto=max` e `--auto=benchmark`, detectando threads, RAM e WSL para sugerir `-t`, `-k` e `-n`.
- **Uso ideal:** Encontrar chaves em intervalos conhecidos com velocidade astronômica. Requer RAM.
- **Exemplo (Puzzle 66):**
  ```bash
  ./BSGS/modo-bsgs -f Puzzles/66.txt -b 66 -t 8 -s 10
  ```
  ```bash
  ./BSGS/modo-bsgs --auto=balanced -f Puzzles/66.txt -b 66
  ```

### 🦘 3. Kangaroo Engine (`modo-kangaroo`)
Motor de alta performance baseado no algoritmo *Pollard's Kangaroo*, agora totalmente **Standalone (C++)** e unificado com paridade total de recursos.
- **Standalone Premium**: Inclui interface visual colorida (ANSI), geração nativa de WIF e Bitcoin Address.
- **Independência Total**: Não requer orquestradores externos para a lógica de saltos.
- **Multithreading Nativo**: Escala linearmente com todos os núcleos da CPU (`-t`).
- **Nomenclatura por Range**: Suporta a flag `-b` para organizar checkpoints de forma granular (ex: #66, #120).
- **Checkpoint Portátil v3**: Salva e retoma o estado da frota, traps em RAM e parâmetros ativos de tuning.
- **Archive por Shard**: Descarrega armadilhas excedentes para arquivos `traps_archive_shard_*.bin`, reduzindo custo do caminho de disco.
- **Tuning em Runtime**: Permite ajustar saltos ativos com `-j` e a quantidade de kangaroos `wild` com `-w`.
- **Auto-Tuning V1**: Suporta `--auto`, `--auto=safe`, `--auto=balanced` e `--auto=max`, detectando threads, RAM e WSL para sugerir `-t`, `-d`, `-m`, `-j` e `-w`.
- **Hot Path Otimizado**: Distâncias saíram do GMP no loop principal e o cache afim foi reaproveitado para reduzir custo por hop.
- **Uso ideal**: O melhor para ranges gigantes (ex: puzzles 100+) onde o BSGS consumiria RAM impossível.
- **Exemplo (Puzzle 130):**
  ```bash
  ./kangaroo/modo-kangaroo -p <PUBKEY_HEX> -b 130 -r 0:FFFFFFFFFFFFFFFF -t 12 -d 22 -j 48 -w 40
  ```
  ```bash
  ./kangaroo/modo-kangaroo --auto=balanced -p <PUBKEY_HEX> -b 130 -r 0:FFFFFFFFFFFFFFFF
  ```

---

## 💾 Sistema de Checkpoints Unificado (v2.0)

Implementamos um sistema de persistência robusto e interativo em todos os motores para garantir que você nunca perca o progresso de uma busca de longa duração.

### 🔄 Como Funciona
1. **Nomenclatura Dinâmica**: Para evitar que o progresso de um puzzle sobrescreva outro, os arquivos são nomeados por módulo e bit-range:
   - `address_bit66.ckp`
   - `bsgs_bit66.ckp`
   - `kangaroo_bit66.ckp`
2. **Retomada de Checkpoint**:
   - `modo-address` e `modo-bsgs` mantêm o fluxo interativo de confirmação ao detectar checkpoint compatível.
   - `modo-address` e `modo-bsgs` também aceitam retomada não interativa via `QCHAVES_AUTO_RESUME=1` ou descarte automático via `QCHAVES_AUTO_RESUME=0`.
   - `modo-kangaroo` carrega automaticamente checkpoints compatíveis do formato atual.
3. **Resiliência de Energia (Auto-Save)**: O progresso é salvo automaticamente a cada **5 minutos**.
4. **Interrupção Segura (Ctrl+C)**: Todos os módulos capturam o sinal de interrupção e realizam um salvamento de emergência do estado exato antes de fechar.

---

## 🦅 Cuckoo Filter: O Novo Padrão de Busca

Substituímos o antigo sistema de *Bloom Filters* pela arquitetura **Cuckoo Filter**, trazendo uma evolução massiva em performance e eficiência de cache em toda a suite.

### 🚀 Por que Cuckoo?
- **Cache Local Friendly:** Diferente do Bloom Filter, que espalha bits aleatoriamente pela RAM (causando muitos *cache misses*), o Cuckoo Filter organiza os dados em baldes contíguos. Isso permite que a CPU verifique se uma chave existe mantendo os dados no cache L1/L2.
- **XXHash Otimizado:** Utilizamos o algoritmo `XXHash64` para geração de fingerprints, garantindo colisões mínimas e velocidade superior a qualquer hash tradicional.
- **Menor Falsa Positividade:** Com o mesmo uso de memória, o Cuckoo Filter oferece uma taxa de erro significativamente menor que os filtros anteriores.

### ⚠️ Importante: Migração de Arquivos (`.blm` → `.ckf`)
A nova arquitetura **não é compatível** com os arquivos de tabela antigos.
- **Nova Extensão:** Os arquivos de filtro agora utilizam a extensão **`.ckf`** (ex: `keyhunt_bsgs_4_1.ckf`).
- **Ação Requerida:** Você deve excluir seus arquivos `.blm` antigos e gerar as novas tabelas usando a versão atual dos módulos. O programa informará caso detecte arquivos legados.

---

## 📖 Exemplo Rápido de Uso

Para rodar o motor de endereços no range do puzzle 66 a partir da pasta `Modulos/`:
```bash
./Address/modo-address -f ../Puzzles/66.txt -b 66 -l compress -R -t 8 -s 10
```

## ⚙️ Explicação dos Parâmetros

Aqui estão os detalhes técnicos dos comandos mais utilizados:

| Parâmetro | Descrição | Exemplo |
| :--- | :--- | :--- |
| **`-b`** | **Bit Range**: Define o intervalo da busca baseado em potências de 2. | `-b 66` (Entre $2^{65}$ e $2^{66}$) |
| **`-f`** | **File**: Carrega o arquivo com o alvo (PubKey/Address). | `-f Puzzles/120.txt` |
| **`-t`** | **Threads**: Número de núcleos do CPU para processamento. | `-t 8` (Usa 8 núcleos) |
| **`-k`** | **K-Factor**: Fator de memória (RAM) para o BSGS. | `-k 1024` (Usa ~16GB RAM) |
| **`-s`** | **Stats Interval**: Frequência de atualização (em segundos). | `-s 10` (Atualiza a cada 10s) |
| **`-j`** | **Active Jumps**: Número de saltos ativos do Kangaroo. | `-j 48` |
| **`-w`** | **Active Wild**: Número de kangaroos `wild` na frota do Kangaroo. | `-w 40` |
| **`--auto`** | **Auto Profile**: Aplica tuning automático por hardware. Suporta `safe`, `balanced`, `max` e `benchmark`. | `--auto=balanced` |

### 🛠️ Auto-Tuning (--auto)

Todos os motores agora suportam **auto-detecção de hardware** com profiles ajustáveis:

```bash
--auto           # Usa perfil 'balanced' por padrão
--auto=safe      # Parâmetros conservadores (metade dos recursos)
--auto=balanced # Equilíbrio entre performance e recursos
--auto=max       # Usa todos os recursos disponíveis
--auto=benchmark # Testa múltiplas combinações e salva o melhor perfil em ~/.qchaves_profile.json
```

#### Motores Suportados

| Motor | Parâmetros Automáticos |
| :--- | :--- |
| **Address** | `-t` (threads) |
| **BSGS** | `-t` (threads), `-k` (k-factor), `-n` (tamanho da tabela) |
| **Kangaroo** | `-t` (threads), `-d` (dp_bits), `-m` (memória), `-j` (jumps), `-w` (wild) |

O que é detectado automaticamente:
- **threads lógicas**: Número de CPUs/threads disponíveis
- **RAM total**: Memória total do sistema
- **RAM disponível**: Memória livre no momento
- **Ambiente WSL**: Ajuste automático para ambiente Windows/WSL
- **Perfil de hardware**: Baixa/média/alta performance

Os valores escolhidos automaticamente podem ser sobrescritos manualmente. Overrides sempre vencem:
```bash
# Usa profile 'max' mas força 8 threads
./BSGS/modo-bsgs --auto=max -t 8 -f Puzzles/66.txt -b 66
```

### ⚙️ Configurando Performance e Memória

O desempenho dos motores depende diretamente da configuração dos parâmetros `-t` e `-k`.

#### Parâmetro `-t` (Threads)
Defina `-t` conforme o número de threads do seu processador. Para saber quantos núcleos você tem, use `nproc` no WSL.
- Exemplo: Se você tem um processador com 16 threads, use `-t 16`.

#### 2. Parâmetro `-k` (Memory Factor) e `-n` (N-Sequential)

Utilizado no motor **BSGS**, o parâmetro `-k` escala a quantidade de "Baby Steps" em RAM. Quanto maior o `-k`, mais rápida é a busca, mas exige mais memória. Em sistemas com muita RAM, o parâmetro `-n` também deve ser ajustado para otimizar o ciclo de busca.

> [!CAUTION]
> **Aviso sobre SWAP:** O programa **NÃO funciona** corretamente com memória Swap. Ele foi projetado para pequenos pedaços de memória física real. O uso de Swap causará lentidão extrema e pode resultar em VELOCIDADE incorreta ou perda de "hits".
> 
> Se você exceder o valor máximo de `-k` suportado pela sua RAM real, o programa terá desempenho subótimo e comportamento imprevisível.

**Tabela de Referência de RAM (Otimizada para Cuckoo):**

| RAM Disponível | Parâmetros Recomendados |
| :--- | :--- |
| **2 GB** | `-k 256` |
| **4 GB** | `-k 512` |
| **8 GB** | `-k 1024` |
| **16 GB** | `-k 2048` |
| **32 GB** | `-k 4096` |
| **64 GB** | `-n 0x100000000000 -k 8192` |
| **128 GB** | `-n 0x400000000000 -k 16384` |
| **256 GB** | `-n 0x400000000000 -k 32768` |
| **512 GB** | `-n 0x1000000000000 -k 32768` |
| **1 TB** | `-n 0x1000000000000 -k 65536` |
| **2 TB** | `-n 0x4000000000000 -k 65536` |
| **4 TB** | `-n 0x4000000000000 -k 131072` |
| **8 TB** | `-n 0x10000000000000 -k 131072` |

## 💎 Saída e Resultados (Premium UI)

A suíte Qchaves agora conta com uma interface de saída **Premium** no console e logs estruturados para facilitar a importação imediata de fundos.

### 🎨 Visual de "Hit" no Console
Ao encontrar uma chave privada, o programa exibe um box formatado com cores ANSI (em todos os módulos):
- **Sinalização Visual:** Box Verde (Bitcoin) ou Roxo (Ethereum) com status de sucesso.
- **Puzzle ID:** Identificação automática do range de bits (ex: #66).
- **Formatos Inclusos:** Chave Privada (Hex/Dec), Publickey e Endereço.
- **WIF Nativo:** Geração automática do **WIF Format** (Wallet Import Format), pronto para ser copiado e colado em qualquer carteira como Electrum, BlueWallet ou Core.

### 💾 Arquivo `FOUND_KEYS.txt`
As chaves encontradas não são apenas exibidas, mas salvas permanentemente.
- **Novo Nome:** O antigo `KEYFOUNDKEYFOUND.txt` foi substituído pelo mais limpo **`FOUND_KEYS.txt`**.
- **Formato:** Salvo em texto puro estruturado (ASCII) para máxima compatibilidade com qualquer editor de texto.

---

> [!TIP]
> - Use sempre o parâmetro `-t` seguido do número de núcleos do seu processador para obter a performance máxima.
> - Para o **BSGS**, o parâmetro `-k` (fator de memória) agora é 50% mais eficiente graças ao Cuckoo Filter.
> - O **modo-address** agora utiliza atualização incremental de ponto (v2.1), tornando-o significativamente mais rápido em buscas sequenciais.
> - Ao encontrar uma chave, use o **WIF Format** gerado no console para importar diretamente seus fundos sem precisar de conversores externos.

---

## 🤝 Créditos & Referências

Este projeto foi construído e otimizado com base em excelentes trabalhos da comunidade. Agradecimentos especiais aos desenvolvedores dos projetos que serviram de base:

- [Cacachave](https://github.com/lmajowka/cacachave)
- [Keyhunt](https://github.com/albertobsd/keyhunt)
