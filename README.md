# monitor-cves

Monitor de vulnerabilidades em Python: busca CVEs em uma API pública, filtra por gravidade e avisa quando surgem falhas novas.

![Status](https://img.shields.io/badge/status-em%20desenvolvimento-yellow)
![Python](https://img.shields.io/badge/python-3.x-blue)

## Sobre o projeto

**CVE** (*Common Vulnerabilities and Exposures*) é o identificador público de uma falha de segurança, como `CVE-2024-12345`. Acompanhar essas falhas manualmente dá trabalho, então este projeto automatiza o processo:

- busca vulnerabilidades em uma API pública;
- filtra e ordena por gravidade e produto;
- salva os resultados e envia alertas;
- exibe tudo em um painel web.

## Roadmap

- [x] Estrutura inicial do repositório
- [ ] Buscar dados da API (`requests`, JSON)
- [ ] Organizar em funções com tratamento de erros
- [ ] Filtrar e ordenar por gravidade e produto
- [ ] Salvar resultados em CSV/JSON
- [ ] Automatizar com aviso por e-mail ou Telegram
- [ ] Armazenar em banco de dados (SQLite)
- [ ] Painel web (Flask/FastAPI + HTML/CSS/JS)
- [ ] Testes (`pytest`), documentação final e deploy

## Tecnologias

- Python
- Requests
- SQLite
- Flask ou FastAPI
- HTML, CSS e JavaScript

## Como rodar

```bash
# clonar o repositório
git clone https://github.com/math825/monitor-cves.git
cd monitor-cves

# criar e ativar o ambiente virtual (Windows)
python -m venv .venv
.venv\Scripts\Activate.ps1

# instalar as dependências
pip install -r requirements.txt
```

> O projeto está em desenvolvimento, então as instruções de uso serão adicionadas conforme as funcionalidades forem concluídas.

## Autor

**Matheus Bueno do Nascimento**  
[GitHub](https://github.com/math825)