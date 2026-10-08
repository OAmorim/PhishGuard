# PhishGuard — instalação simples

Requisitos: Python 3.12. Git é necessário apenas para clonar; VS Code é opcional. Executar os comandos na raiz do projeto.

## 1. Obter o projeto

```powershell
git clone https://github.com/OAmorim/PhishGuard.git
cd PhishGuard
```

Se já tiveres a pasta, basta abri-la no terminal.

## 2. Instalar e abrir

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Não é necessário ativar o ambiente virtual nem alterar a política de execução do PowerShell. Num novo computador, cria um ambiente novo; não copies `.venv`.

Nas utilizações seguintes, basta o último comando. A aplicação abre normalmente em `http://localhost:8501`. Para a parar: `Ctrl+C`. Se a porta estiver ocupada, acrescenta `--server.port 8505`.

## 3. Escolher o modo

| Modo | O que é necessário | O que fica disponível |
| --- | --- | --- |
| Heurísticas | Apenas a instalação acima | Cabeçalhos, URLs, linguagem e pontuação |
| ML e decisão híbrida | Modelo local treinado | Probabilidade ML e HIGH / REVIEW / LOW |
| Explicação LLM | Modelo ML, Ollama em execução e Qwen2.5 3B | Explicação opcional da avaliação existente |

Sem o modelo ML, a app continua a funcionar, mas a avaliação híbrida e a explicação LLM ficam indisponíveis. Os modelos e datasets não são distribuídos neste repositório.

### ML (opcional)

Coloca o dataset de treino em `data/raw/Balanced_Dataset.csv`, com `body` e `label` (`0` legítimo, `1` phishing), e executa:

```powershell
.\.venv\Scripts\python.exe -m training.train_model
```

O treino cria `models/phishing_model.joblib` e atualiza `results/ml_metrics.json`. Pode demorar e requer memória; não é um passo necessário para experimentar as heurísticas. Consulta [datasets e reprodução](docs/DATASETS.md) antes de obter dados. Carrega apenas modelos joblib de confiança e com versões compatíveis.

### Ollama / LLM (opcional)

Instala o Ollama separadamente, mantém o serviço em execução e prepara o modelo:

```powershell
ollama pull qwen2.5:3b
```

Na aplicação, ativa “Generate local AI analyst explanation” antes de analisar. O código contacta `http://localhost:11434/api/generate`. O LLM explica a classificação existente; não a decide. A primeira resposta pode demorar enquanto o modelo carrega.

## Testes e desenvolvimento (opcional)

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
```

Os testes não exigem datasets, modelo treinado nem Ollama. O workflow `.github/workflows/tests.yml` executa-os no GitHub quando houver push ou pull request.

Se as importações numéricas bloquearem num ambiente restrito, tenta apenas nessa sessão:

```powershell
$env:OPENBLAS_NUM_THREADS = '1'
$env:OMP_NUM_THREADS = '1'
```

Em VS Code, seleciona `.venv\Scripts\python.exe` como interpretador. Não é necessário instalar extensões para correr a app pelo terminal.

## Exemplos para uma demonstração

Carrega estes ficheiros através de “Upload .eml”:

- `samples/phishing/test_phishing.eml`: phishing PayPal; HIGH com o modelo usado nas capturas.
- `samples/legitimate/purchase_confirmation.eml`: compra legítima; REVIEW com esse modelo.
- `samples/legitimate/meeting_reminder.eml`: lembrete de reunião; LOW com esse modelo.

São exemplos sintéticos, não emails privados. Os resultados ML podem mudar se treinares um modelo diferente.

## Antes de publicar

```powershell
git status --short
git diff --check
```

Revê apenas os ficheiros pretendidos. Não incluas `.venv`, datasets, modelos, credenciais ou emails privados. Os relatórios por amostra em `results/` contêm IDs locais, rótulos e previsões, não o texto original dos emails. O histórico anterior pode ainda conter versões com texto; não foi reescrito nesta revisão.
