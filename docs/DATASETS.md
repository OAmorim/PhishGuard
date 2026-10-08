# Datasets and reproduction / Dados e reprodução

Raw datasets and trained models are local and ignored by Git. Sources and publisher-declared licences were verified on 8 October 2026 against official repositories and Zenodo metadata. The local files match the published files as detailed below. The original download dates are not known; verification date is not a download date.

Os datasets e modelos permanecem locais e ignorados pelo Git. As fontes e licenças declaradas pelos autores foram verificadas em 8 de outubro de 2026. Os ficheiros locais correspondem aos ficheiros públicos. As datas originais de download não foram registadas.

## Verified sources and attribution / Fontes e atribuição verificadas

| Local file | Authors / Autores | Official source / Fonte oficial | Declared licence / Licença declarada | Identity verification / Verificação |
| --- | --- | --- | --- | --- |
| `Balanced_Dataset.csv` | Abeer Alhuzali, Ahad Alloqmani, Manar Aljabri, Fatemah Alharbi | [Phishing-Email-Detection-Dataset, Zenodo v2, 10 October 2025](https://doi.org/10.5281/zenodo.17314806) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) | Local MD5 matches published MD5: `c18127659164566291c18803cc7d4c5f` |
| `Phishing_validation_emails.csv` | Radoslav Miltchev, Dimitar Rangelov, Evgeni Genchev | [Phishing validation emails dataset, Zenodo v1, 29 August 2024](https://doi.org/10.5281/zenodo.13474746) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) | Local MD5 matches published MD5: `1bf8ec0fe3f67e12dd275ce5b2b91b69` |
| `ephishLLM.json` | Luca Pajola, Eugenio Caripoti, Simeone Pizzi, Mauro Conti, Stefan Banzer, Giovanni Apruzzese | [Official GitHub repository](https://github.com/pajola/e-phishGen), [authors' Hugging Face dataset card](https://huggingface.co/datasets/pajola/e-phishGen/blob/main/README.md) | MIT, declared in the authors' Hugging Face metadata | Byte-for-byte match with GitHub `main/ephishLLM.json`; SHA-256 below |

Zenodo licence evidence: [training record API](https://zenodo.org/api/records/17314806) and [validation record API](https://zenodo.org/api/records/13474746), both `metadata.license.id = cc-by-4.0`. The E-PhishGen card declares `license: mit`; the GitHub tree does not provide a separate LICENSE file. Preserve that declaration and obtain the authors' copyright/licence notice before redistributing a dataset copy. The verified README revision is `dda1f1e` (as displayed by Hugging Face); the JSON content hash is the immutable identifier used here.

**Reuse conditions / Condições de reutilização:** CC BY 4.0 requires appropriate credit, a licence link and indication of modifications when sharing. MIT requires preservation of the copyright and permission notice in copies or substantial portions. These are publisher-declared licences; the balanced dataset combines nine corpora, and this verification does not independently audit rights in every underlying email. PhishGuard does not relicense or redistribute the raw datasets. Apache-2.0 applies to the project's original work, not to those third-party inputs.

**Transformations / Transformações:** the raw local files were not changed. Training drops missing entries and deduplicates bodies before the stratified split; validation deduplicates email texts; the final benchmark filters English entries and supplies a synthetic neutral header envelope. Published per-sample CSVs remove source text and retain local IDs, labels and predictions.

**Research citation / Referência:** Pajola, Luca; Caripoti, Eugenio; Pizzi, Simeone; Conti, Mauro; Banzer, Stefan; Apruzzese, Giovanni (2025). *E-PhishGen: Unlocking Novel Research in Phishing Email Detection*. ACM Workshop on Artificial Intelligence Security (AISec). The two Zenodo records above provide the dataset citations and version-specific DOIs.

## Expected inputs / Entradas esperadas

| File under `data/raw/` | Script | Required columns / fields |
| --- | --- | --- |
| `Balanced_Dataset.csv` | `python -m training.train_model` | `body`, `label`; 0 legitimate, 1 phishing |
| `Phishing_validation_emails.csv` | `python -m training.validate_model`, `python -m training.analyze_validation` | `Email Text`, `Email Type`; `Safe Email` / `Phishing Email` |
| `ephishLLM.json` | `python -m training.evaluate_final` | JSON records with `Language`, `Subject`, `Body`, `type`; English records selected with `Language == "en"` |

Run from the repository root with Python 3.12 and `requirements-dev.txt`. The training pipeline deduplicates exact bodies, then uses an 80/20 stratified split with seed 42. Validation deduplicates exact email texts. The final benchmark supplies a neutral synthetic header envelope, since original authentication headers are absent.

The synthetic challenge set is generated from code in `training/create_challenge_set.py` and requires no downloaded dataset:

```powershell
.\.venv\Scripts\python.exe -m training.create_challenge_set
.\.venv\Scripts\python.exe -m training.evaluate_hybrid
```

The second command requires the trained model. Evaluation commands overwrite their corresponding reports; preserve earlier reports if comparing runs.

## Local file fingerprints / Identificação dos ficheiros locais

Recorded on 8 October 2026. Hashes identify the exact local files; they do not identify their publisher, prove a licence, or validate labels.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `Balanced_Dataset.csv` | 358,769,548 | `ac83bf86beabbff654848e6f94389c0723d100865a3f7f2fc4299607c85c7569` |
| `Phishing_validation_emails.csv` | 203,107 | `ad15f63cb8db2caaee33c442f1ff4488b9444530a4c42ab63bb580016b160bd3` |
| `ephishLLM.json` | 12,275,474 | `56420b143e30343f6db723c3716e10abec9f72a67ba99ae2cc7c3a87b547f51f` |

## Published results / Resultados públicos

`results/final_benchmark_results.csv` and `results/external_validation_predictions.csv` now publish numerical results without source bodies or subjects. `sample_id` is the zero-based row position after the respective English filter or deduplication; it is local to that evaluation, not a global email identifier. Labels and predictions were preserved during removal of the text columns.

Aggregate JSON reports and the threshold table remain unchanged. Existing Git history may still contain source email content from earlier CSV versions. No history rewrite has been performed.

## Reproducibility boundary / Limite da reprodução

Sources, publisher-declared licences and local file identities are now verified. Download dates and the exact historical training environment remain unknown. The current pinned requirements record the working environment reviewed here, not proof of the exact environment that produced every historical metric. Download the files from the official sources into `data/raw/` and compare the hashes before rerunning evaluations.
