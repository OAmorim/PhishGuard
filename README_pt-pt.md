# PhishGuard

[English](README.md) | **Português (Portugal)**

Projeto de portefólio de cibersegurança para triagem de emails: heurísticas explicáveis, um classificador TF-IDF + regressão logística, um motor de decisão híbrido e explicações opcionais geradas localmente com Ollama. Desenvolvido para demonstrar competências de investigação técnica e avaliação relevantes para funções de cibersegurança e SOC.

## Como funciona

```text
Email original (texto ou ficheiro .eml)
    -> Parser de email
    -> Indicadores de URLs, linguagem e cabeçalhos -> Pontuação heurística
    -> Corpo do email -> TF-IDF + regressão logística -> Previsão de ML
    -> Motor híbrido -> HIGH / REVIEW / LOW
    -> Explicação determinística e ações recomendadas
    -> Explicação opcional com LLM local (não classifica)
```

A pontuação heurística está limitada a 100. Cada tipo de indicador é contabilizado uma única vez por fonte. Pontuações inferiores a 30 correspondem a LOW, de 30 a 59 a MEDIUM e de 60 a 100 a HIGH. Estes valores são pontos heurísticos, não probabilidades.

O classificador de aprendizagem automática (ML) utiliza o corpo extraído do email e um limiar de phishing de **0,50**. A probabilidade prevista é uma saída do modelo, não uma garantia nem uma medida calibrada do risco real.

| Resultado heurístico | Previsão de ML | Avaliação final |
| --- | --- | --- |
| MEDIUM ou HIGH | PHISHING | HIGH |
| LOW | LEGITIMATE | LOW |
| Restantes combinações | Qualquer | REVIEW |

REVIEW indica discordância entre os métodos. LOW significa pouca evidência detetada; não estabelece que o email seja seguro. Se o modelo treinado não estiver disponível, a análise heurística continua a funcionar, mas a avaliação híbrida fica indisponível.

## Funcionalidades

- Colar o email original ou carregar um ficheiro `.eml`, com suporte para texto, bytes e mensagens multipart com corpos em texto simples ou HTML.
- Extrair os cabeçalhos From, To, Subject, Reply-To, Return-Path e Authentication-Results.
- Detetar diferenças entre domínios e interpretar os resultados SPF, DKIM e DMARC fornecidos nos cabeçalhos.
- Identificar URLs HTTP, destinos com endereços IP, encurtadores, Punycode e indicadores associados a determinados TLDs.
- Detetar linguagem comum de urgência, ameaça, pedidos de credenciais e pagamentos, em inglês.
- Apresentar evidências heurísticas, previsão de ML, avaliação híbrida e ações recomendadas.
- Explicar opcionalmente o resultado existente através do Ollama local (`qwen2.5:3b`). São enviados apenas resultados estruturados da análise; o corpo original do email não é enviado ao LLM.

## Processo técnico de deteção

### 1. Parsing do email e extração de evidências

O módulo [`src/email_parser.py`](src/email_parser.py) utiliza o pacote `email` do Python com `policy.default`: `Parser` para texto colado e `BytesParser` para os bytes de ficheiros `.eml`. Extrai From, To, Subject, Reply-To, Return-Path e todos os cabeçalhos Authentication-Results. Nas mensagens multipart prefere `text/plain`, recorrendo a `text/html` quando necessário; o BeautifulSoup converte HTML em texto visível.

A utilização de dois textos de entrada diferentes é intencional: o analisador de linguagem recebe **assunto + corpo**, enquanto o classificador de ML recebe **apenas o corpo**, em coerência com o processo de treino. Os cabeçalhos e as URLs constituem sinais heurísticos separados.

### 2. Análise de cabeçalhos e autenticação

O módulo [`src/header_analyzer.py`](src/header_analyzer.py) extrai endereços com `email.utils.parseaddr` e utiliza `tldextract` para comparar domínios registados, em vez dos nomes completos dos hosts. Por exemplo, `security.example.com` e `mail.example.com` partilham o domínio registado `example.com`; um Reply-To com outro domínio registado origina um indicador de divergência.

O SPF avalia normalmente se o host remetente está autorizado a enviar para o domínio do remetente do envelope. O DKIM verifica uma assinatura de domínio sobre o conteúdo e os cabeçalhos assinados. O DMARC utiliza os resultados SPF/DKIM e o alinhamento com o domínio visível em From. **O PhishGuard não executa estes protocolos:** interpreta os resultados já presentes em Authentication-Results através de uma expressão regular que não distingue maiúsculas de minúsculas. A confiança nesses cabeçalhos depende da fronteira de confiança do sistema de receção de correio.

| Indicador | Pontos | Comportamento |
| --- | ---: | --- |
| Domínio do remetente ausente ou inválido | 10 | A extração do remetente não produziu um domínio |
| Divergência From / Reply-To | 15 | Os domínios registados são diferentes |
| Divergência From / Return-Path | 5 | Os domínios registados são diferentes; o reencaminhamento legítimo também pode causar isto |
| SPF fail ou softfail | 15 | O resultado de autenticação fornecido indica uma falha |
| DKIM fail | 15 | O resultado fornecido indica uma falha |
| DMARC fail | 25 | O resultado fornecido indica uma falha |
| neutral, none, temperror ou permerror | 3 por protocolo | Resultado inconclusivo com peso reduzido |

Uma divergência constitui evidência para investigação, não prova de falsificação do remetente. Listas de distribuição, serviços terceiros e reencaminhamentos podem gerar diferenças legítimas. A autenticação bem-sucedida também não prova que o conteúdo seja benigno.

### 3. Análise de URLs

O módulo [`src/url_analyzer.py`](src/url_analyzer.py) extrai strings HTTP/HTTPS do corpo legível, remove pontuação final comum e interpreta-as com `urllib.parse.urlparse`. O módulo `ipaddress` reconhece destinos com endereços IP e `tldextract` identifica domínios registados e sufixos. As URLs malformadas são toleradas para evitar que um único valor inválido interrompa a análise.

| Sinal | Pontos | Método de deteção |
| --- | ---: | --- |
| HTTP | 10 | O esquema da URL é `http` |
| Destino IP | 25 | O hostname é um endereço IPv4 ou IPv6 válido |
| Encurtador de URLs | 15 | O domínio registado pertence a um conjunto configurado, por exemplo `bit.ly` |
| Punycode | 25 | O hostname contém `xn--` |
| TLD selecionado | 10 | O sufixo pertence a um conjunto configurado, por exemplo `xyz`, `top` ou `click` |

Estas verificações analisam a sintaxe das URLs e listas configuradas. Não existe consulta de reputação em tempo real, investigação DNS, seguimento de redirecionamentos nem obtenção do conteúdo dos sites. HTTP, domínios internacionalizados e os TLDs selecionados podem ocorrer em emails legítimos; são sinais ponderados, não veredictos isolados.

### 4. Análise de engenharia social

O módulo [`src/keyword_analyzer.py`](src/keyword_analyzer.py) aplica expressões regulares com limites de palavra, sem distinguir maiúsculas de minúsculas, ao assunto e corpo do email. Agrupa as frases encontradas por categoria e devolve o texto correspondente para inspeção.

| Categoria | Pontos | Exemplos de frases detetadas |
| --- | ---: | --- |
| Urgência | 10 | `urgent`, `immediately`, `within 24 hours` |
| Ameaça | 10 | `account has been suspended`, `failure to verify` |
| Pedido de credenciais | 20 | `verify your identity`, `enter your password`, `login` |
| Pedido financeiro | 20 | `bank details`, `wire transfer`, `credit card` |
| Apelo à ação | 5 | `click here`, `open the attachment` |

Cada categoria contribui uma única vez, mesmo que várias frases correspondam aos padrões. Mensagens legítimas de segurança ou finanças podem utilizar a mesma linguagem; a interpretação conjunta com outros sinais reduz a dependência exclusiva da redação.

### 5. Pontuação heurística explicável

O módulo [`src/risk_engine.py`](src/risk_engine.py) soma os pesos configurados, eliminando repetições por `(fonte, tipo de indicador)`. Repetir o mesmo indicador HTTP em várias URLs não aumenta a sua contribuição. O motor devolve `raw_score`, `score` limitado, `level` e um `breakdown` com a fonte, mensagem e pontos de cada contribuição.

```text
raw_score = soma dos pesos dos indicadores únicos por fonte
score = min(raw_score, 100)
LOW: 0–29 | MEDIUM: 30–59 | HIGH: 60–100
```

Os pesos e limiares são escolhas heurísticas definidas manualmente, não probabilidades ajustadas ou calibradas. O detalhe das contribuições permite explicar porque foi gerado um alerta e discutir causas de falsos positivos.

### 6. Classificação por aprendizagem automática

O script [`training/train_model.py`](training/train_model.py) remove registos sem corpo ou rótulo e corpos exatamente duplicados, converte os rótulos em inteiros e realiza uma divisão estratificada de 80% para treino e 20% para teste, com `random_state=42`.

O `Pipeline` do scikit-learn ajusta o vetorizador e o classificador aos dados de treino:

- **TF-IDF:** texto em minúsculas; unigramas e bigramas de palavras; até 50 000 características; `min_df=2`; `max_df=0.98`; frequência de termos sublinear. Representa palavras e frases curtas pela frequência relativa ao conjunto de textos de treino.
- **Regressão logística:** `max_iter=1000`, `random_state=42`. Aprende uma fronteira linear sobre as características TF-IDF e disponibiliza probabilidades de classe através de `predict_proba`.
- **Inferência:** [`src/ml_classifier.py`](src/ml_classifier.py) encontra a classe `1` em `model.classes_`, obtém a sua probabilidade e prevê PHISHING quando `p >= 0.50`.
- **Persistência:** o joblib guarda o pipeline completo. O `app.py` mantém o modelo carregado em cache com `st.cache_resource`.

O classificador pode identificar padrões textuais aprendidos para além da lista explícita de palavras-chave, mas não autentica o remetente nem determina a reputação de uma URL. A remoção de corpos exatamente duplicados reduz uma fonte de contaminação entre treino e teste; não demonstra a ausência de mensagens quase duplicadas ou de modelos de texto relacionados. A avaliação externa é, por isso, essencial.

### 7. Avaliação híbrida e explicação determinística

O módulo [`src/hybrid_engine.py`](src/hybrid_engine.py) aplica a tabela de decisão apresentada acima, em vez de calcular uma média entre pontos heurísticos e probabilidade de ML. Isto preserva o significado dos dois sinais e torna a discordância explícita. O módulo [`src/explanation_engine.py`](src/explanation_engine.py) gera o resumo, as evidências e as ações recomendadas a partir do resultado já determinado.

O exemplo de confirmação de compra ilustra esta escolha: o motor heurístico devolve `0/100`, mas o modelo treinado prevê PHISHING com cerca de `77,1%` de probabilidade. O resultado final é **REVIEW**, permitindo investigar a divergência sem tratar qualquer dos métodos como definitivo.

## LLM local: explicação para o analista após a classificação

O módulo [`src/llm_explainer.py`](src/llm_explainer.py) acrescenta uma explicação em linguagem natural através de **Ollama + Qwen2.5 3B**. O LLM não define a pontuação, a probabilidade de ML nem a avaliação final. Converte as evidências existentes num resumo orientado para o analista e em próximos passos.

```text
Resultado heurístico + resultado de ML
        -> Avaliação híbrida (regras em Python)
        -> Contexto estruturado e concordância/discordância explícita
        -> Prompt com restrições
        -> Pedido POST local ao Ollama em /api/generate
        -> Assessment / Key evidence / Recommended action
```

### Dados enviados ao LLM

A função `build_llm_context()` cria um JSON com a avaliação final, a relação entre os métodos, o motivo de revisão, a pontuação e nível heurísticos, a previsão e probabilidade de ML e as contribuições das evidências ponderadas. Neste contexto, a probabilidade é expressa em percentagem, arredondada a duas casas decimais.

Exemplo ilustrativo do contexto para o caso de compra. Os identificadores e as mensagens mantêm-se em inglês porque correspondem ao formato real da implementação:

```json
{
  "final_assessment": "REVIEW",
  "analysis_relationship": "DISAGREEMENT",
  "review_reason": "The heuristic analysis detected low phishing risk, while the machine learning model classified the email as PHISHING with a probability of 77.12%.",
  "heuristic_score": 0,
  "heuristic_level": "LOW",
  "ml_prediction": "PHISHING",
  "ml_phishing_probability": 77.12,
  "evidence": []
}
```

O corpo original do email é excluído. Isto reduz a exposição a instruções presentes no email e a conteúdo desnecessário; não demonstra imunidade a injeção de instruções no prompt nem torna todo o contexto estruturado não sensível. A execução local evita enviar este pedido de explicação para um serviço externo de LLM.

### Restrições do prompt e parâmetros de geração

A função `build_prompt()` indica que a classificação já está determinada e exige três secções: **Assessment**, **Key evidence** e **Recommended action**. Instrui o modelo a preservar a decisão, utilizar apenas as evidências fornecidas, não inventar pontuações ou certezas, explicar a discordância nos casos REVIEW e não expor nomes internos dos indicadores. Dá prioridade às evidências técnicas de autenticação e remetente face aos sinais de linguagem.

A função `generate_llm_explanation()` envia um pedido JSON para `http://localhost:11434/api/generate` com:

| Parâmetro | Valor | Objetivo |
| --- | --- | --- |
| Modelo | `qwen2.5:3b` | Modelo local de explicação |
| Temperatura | `0.2` | Favorecer uma redação relativamente consistente |
| Limite de tokens | `num_predict=220` | Limitar o comprimento da explicação |
| Streaming | `false` | Receber uma resposta completa |
| Keep alive | `10m` | Manter o modelo carregado entre pedidos |
| Tempo limite | `120` segundos | Limitar a espera pela explicação opcional |

Estas opções são instruções de prompt e parâmetros de geração, não garantias de cumprimento. Uma temperatura baixa não torna o LLM totalmente determinístico. O código verifica se a resposta está vazia, mas não valida todas as afirmações nem obriga a resposta a cumprir um esquema interpretado pelo programa. A aplicação apresenta erros de ligação ou de tempo limite sem alterar os resultados existentes da deteção.

### O que é testado

Os testes do LLM verificam o contexto estruturado, a concordância/discordância, o motivo explícito de revisão, as restrições do prompt, as ações adequadas e a exclusão do email original. **Não** demonstram que todas as respostas geradas respeitam o prompt. As capturas seguintes são exemplos observados, não uma avaliação sistemática da qualidade do LLM.

### Exemplos de respostas reais do LLM

Estas capturas focam a explicação gerada, em complemento às três capturas HIGH / REVIEW / LOW da secção de resultados da aplicação. A interface e as explicações permanecem em inglês; esta tradução não altera o idioma da aplicação nem o suporte linguístico dos detetores.

**HIGH — explicação dos indicadores técnicos e recomendações de escalamento**

![Explicação local do LLM para evidências de phishing HIGH e ações recomendadas](docs/screenshots/llm-high-risk.png)

**REVIEW — discordância explícita entre heurísticas e ML, com probabilidade de 77,12%**

![Explicação local do LLM para REVIEW por discordância entre pouca evidência heurística e previsão de phishing](docs/screenshots/llm-manual-review.png)

**LOW — pouca evidência detetada, sem afirmar que o email é seguro**

![Explicação local do LLM para LOW, com indicação explícita de que a segurança não está garantida](docs/screenshots/llm-low-evidence.png)

Esta resposta LOW mantém a avaliação, descreve a concordância entre os métodos e indica expressamente que pouca evidência não garante segurança.

**Limitação observada:** nesta resposta REVIEW, o modelo explica corretamente a discordância, mas utiliza a expressão “ensure its legitimacy”. Esta formulação é demasiado confiante e contraria as instruções do prompt. A resposta HIGH também omite falhas de autenticação apesar da prioridade definida no prompt. Os exemplos mostram que restrições no prompt não equivalem a validação da resposta. A avaliação final e os valores numéricos são calculados de forma independente e não são alterados pela redação gerada. Uma melhoria futura é a validação programática, com recurso à explicação determinística quando a resposta introduz certezas não suportadas.

## Relevância para o portefólio: cibersegurança e triagem em SOC

O projeto demonstra extração de evidências em Python, conceitos de autenticação de email, análise de URLs e domínios, pontuação explicável de alertas, classificação supervisionada de texto, avaliação externa e utilização prudente de um LLM local no trabalho de um analista.

Um analista pode utilizar os resultados para documentar porque uma mensagem é suspeita, separar evidências técnicas de previsões textuais, identificar discordâncias e determinar o que necessita de verificação independente ou escalamento. HIGH apoia a investigação e comunicação do incidente; REVIEW expõe sinais contraditórios; LOW mantém a cautela quando é detetada pouca evidência. A aplicação não executa ações de quarentena, remediação ou comunicação.

Questões de entrevista que a implementação permite discutir:

- Porque comparar domínios registados e porque pode o Return-Path diferir legitimamente de From?
- Porque não garantem os resultados SPF/DKIM/DMARC positivos que o conteúdo seja benigno?
- Porque separar pontuações heurísticas de probabilidades de ML?
- O que explica métricas internas elevadas e resultados externos mais fracos?
- Como afetam os falsos negativos, falsos positivos e a proporção de casos de revisão a carga de trabalho de um SOC?
- Porque excluir o email original do contexto do LLM e o que falta validar na resposta?

Possíveis próximos passos: extrair os destinos dos links HTML, estabelecer a proveniência confiável dos cabeçalhos de autenticação, fixar versões das dependências e dados, melhorar as divisões de avaliação e a calibração, e validar as respostas do LLM face às evidências fornecidas. A integração com SIEM, a análise de anexos e a resposta automatizada são trabalho futuro, não funcionalidades implementadas.

## Execução local (Windows / PowerShell)

É necessário Python 3.12. A partir da raiz do projeto, bastam três comandos:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Não é necessário ativar o ambiente virtual nem alterar a política de execução do PowerShell. Nas utilizações seguintes, basta o último comando. O VS Code é opcional.

| Modo | Requisitos | Funcionalidades disponíveis |
| --- | --- | --- |
| Heurísticas | A instalação acima | Análise de cabeçalhos, URLs, linguagem e risco |
| ML / híbrido | Modelo local `models/phishing_model.joblib` | Probabilidade ML e avaliação HIGH / REVIEW / LOW |
| LLM local | Modelo ML, Ollama e `qwen2.5:3b` | Explicação opcional após a classificação |

Para ML, disponibiliza `data/raw/Balanced_Dataset.csv` com `body` e `label` (0 legítimo, 1 phishing) e executa `.\.venv\Scripts\python.exe -m training.train_model`. O treino guarda o modelo e substitui o relatório de métricas de treino. Carrega apenas modelos joblib de confiança e com versões compatíveis.

Para explicações LLM, instala o Ollama separadamente, executa `ollama pull qwen2.5:3b`, mantém o serviço local em execução e ativa “Generate local AI analyst explanation” na aplicação. O Ollama é opcional e não classifica emails.

Consulta o [guia de instalação resumido](PhishGuard_SETUP.md) para testes e resolução de problemas, e [dados e reprodução](docs/DATASETS.md) para os requisitos de reprodução. As fontes, licenças declaradas e identidade dos datasets estão verificadas e documentadas; o repositório não distribui datasets nem um modelo pré-treinado. As dependências fixadas registam o ambiente revisto, não demonstram o ambiente de todos os benchmarks históricos.

## Capturas de ecrã da aplicação

Os cenários são phishing com referência à PayPal (HIGH), confirmação de compra legítima com discordância entre ML e heurísticas (REVIEW), e um lembrete normal de reunião (LOW).

Os três cenários foram também verificados através do Streamlit AppTest com o modelo local: HIGH = 100/100 e 99,9% de probabilidade ML; REVIEW = 0/100 e 77,1%; LOW = 0/100 e 1,7%. As capturas seguintes mostram a avaliação final; os exemplos de explicação local encontram-se na secção do LLM.

### HIGH — phishing PayPal

![HIGH: pontuação heurística 100/100 e probabilidade ML de phishing 99,9%](docs/screenshots/high-risk.png)

### REVIEW — compra legítima / discordância entre métodos

![REVIEW: pontuação heurística 0/100 e probabilidade ML de phishing 77,1%](docs/screenshots/manual-review.png)

### LOW — lembrete normal de reunião

![LOW: pontuação heurística 0/100 e probabilidade ML de phishing 1,7%](docs/screenshots/low-evidence.png)

## Resultados de avaliação registados

Os valores seguintes provêm dos relatórios versionados em `results/`. São resultados de avaliações já realizadas, não de uma nova execução dos benchmarks em 7 de outubro de 2026.

| Avaliação | Amostras | Exatidão (accuracy) | Precisão | Sensibilidade (recall) | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Teste interno de ML | 39 008 | 98,05% | 97,74% | 98,45% | 98,09% |
| Validação externa completa | 2 000 | 80,05% | 75,19% | 89,70% | 81,81% |
| Validação externa sem duplicados | 100 | 78,00% | 51,16% | 95,65% | 66,67% |
| E-PhishGen em inglês, ML | 11 502 | 68,74% | 76,61% | 57,62% | 65,77% |

O conjunto de validação externa contém 1 900 linhas duplicadas em 2 000 e apenas 100 emails únicos. O resultado sem duplicados é, por isso, a comparação mais informativa. A diferença face ao teste interno revela uma sensibilidade significativa ao conjunto de dados.

### Análise do limiar (100 emails únicos de validação externa)

| Limiar | Exatidão | Precisão | Sensibilidade | F1 |
| --- | ---: | ---: | ---: | ---: |
| 0,30 | 71% | 44,23% | 100% | 61,33% |
| 0,40 | 74% | 46,94% | 100% | 63,89% |
| 0,50 (valor atual) | **78%** | 51,16% | 95,65% | 66,67% |
| 0,60 | 79% | 52,38% | 95,65% | 67,69% |
| 0,75 | 81% | 55,00% | 95,65% | 69,84% |
| 0,85 | 84% | 60,00% | 91,30% | 72,41% |
| 0,90 | 87% | 66,67% | 86,96% | 75,47% |

Aumentar o limiar reduz os falsos positivos à custa da sensibilidade. Estas observações não estabelecem um limiar ótimo para produção.

### Avaliação híbrida

No conjunto sintético de 12 casos, o motor híbrido classificou automaticamente 6, encaminhou 6 para revisão e acertou nos 6 classificados. Trata-se de um conjunto pequeno e ilustrativo, não de evidência de 100% de exatidão geral.

No benchmark E-PhishGen em inglês com 11 502 emails, o motor híbrido classificou 8 131 casos (70,69% de cobertura), encaminhou 3 371 para REVIEW (29,31%) e obteve 70,35% de exatidão entre os casos classificados. Registou 1 falso positivo e 2 410 falsos negativos nesses casos. O benchmark baseia-se no conteúdo e não fornece cabeçalhos originais de autenticação. Os casos de revisão são excluídos da exatidão das decisões; esta métrica não é diretamente comparável à exatidão normal de ML calculada sobre todas as amostras.

Consultar as [métricas de ML](results/ml_metrics.json), [validação externa](results/external_validation_metrics.json), [análise de limiares](results/threshold_analysis.csv), [resumo dos casos sintéticos](results/hybrid_challenge_summary.json) e [benchmark final](results/final_benchmark_summary.json).

## Testes

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

Revisão final de 8 de outubro de 2026: **55 testes passaram em 8,27 segundos com uma instalação nova das dependências** numa cópia sem datasets, modelo treinado ou Ollama. Abrangem parsing, cabeçalhos, URLs, linguagem, risco, decisão híbrida, limiares da inferência de ML, explicações e Streamlit. O `pytest.ini` configura a recolha normal; o workflow do GitHub executa a mesma suite com Python 3.12.

Neste ambiente restrito, as importações numéricas exigiram as seguintes opções de sessão:

```powershell
$env:OPENBLAS_NUM_THREADS = '1'
$env:OMP_NUM_THREADS = '1'
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

Estas opções aplicam-se apenas à sessão do terminal. Os benchmarks históricos não foram executados novamente nesta revisão.

## Estrutura do repositório

```text
app.py                 Interface Streamlit
src/                   Parsing, analisadores, ML, risco, decisão híbrida e explicações
tests/                 Testes unitários e de interface Streamlit
training/              Scripts de treino, validação e avaliação
samples/               Emails .eml sintéticos de exemplo
results/               Relatórios de avaliações realizadas
docs/screenshots/      Capturas de ecrã da aplicação
requirements*.txt      Dependências de execução / testes com versões fixadas
.github/workflows/     Testes automáticos
data/                  Dados locais (ignorados pelo Git)
models/                Modelos treinados locais (ignorados pelo Git)
```

## Limitações

- Ferramenta de triagem para portefólio, não um gateway de email de produção nem um detetor definitivo de phishing.
- O parser lê os resultados de autenticação fornecidos; não verifica SPF, DKIM ou DMARC de forma independente. Cabeçalhos não confiáveis podem ser falsificados e os resultados repetidos são atualmente reduzidos a um resultado por protocolo.
- As heurísticas focam frases em inglês e uma lista reduzida de indicadores. Redações novas e ataques sofisticados podem não ser detetados.
- O HTML é convertido em texto visível; os destinos ocultos dos links podem perder-se. Os anexos não são analisados, os links encurtados não são resolvidos e os sites não são visitados.
- O ML baseado apenas no conteúdo pode confundir linguagem transacional legítima com phishing. As probabilidades apresentadas não foram validadas como confiança calibrada.
- O motor híbrido pode continuar a falhar na deteção de phishing; REVIEW exige investigação humana.
- O LLM recebe um prompt com restrições, mas o texto gerado não é verificado programaticamente quanto a todas as afirmações não suportadas.
- Os relatórios não demonstram desempenho noutra organização, idioma ou distribuição futura de ataques.
- As dependências diretas e a base numérica de ML têm versões fixadas. A reprodução completa exige o ambiente original de treino; as dependências transitivas não estão totalmente fixadas.

Os CSVs de avaliação por amostra publicam IDs locais, rótulos e previsões sem corpos ou assuntos dos emails originais. Versões anteriormente guardadas no Git podem continuar a conter texto no histórico; consulta [DATASETS.md](docs/DATASETS.md).

## Organização e exclusões no Git

O `.gitignore` exclui `data/` (incluindo `data/raw/`), `.venv/`, caches Python, ficheiros de modelos `.joblib`/`.pkl`, segredos do Streamlit e ficheiros locais de ambiente/credenciais. Não incluir emails privados reais nem credenciais em `samples/`, capturas de ecrã ou relatórios.

## Licença

Código e documentação originais: **Apache-2.0**, consultar [LICENSE](LICENSE) e [NOTICE](NOTICE). Os datasets, bibliotecas e modelos de terceiros mantêm as respetivas licenças; consultar [atribuição dos datasets](docs/DATASETS.md). As versões anteriores em MIT mantêm as permissões já concedidas.
