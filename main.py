import csv
import json
import os  
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv  

load_dotenv()  

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves(quantidade, severidade=None, dias=None, palavra=None):
    parametros = {"resultsPerPage": quantidade}

    if severidade:
        parametros["cvssV3Severity"] = severidade
    if palavra:
        parametros["keywordSearch"] = palavra
    if dias:
        fim = datetime.now()
        inicio = fim - timedelta(days=dias)
        formato = "%Y-%m-%dT%H:%M:%S.000"
        parametros["pubStartDate"] = inicio.strftime(formato)
        parametros["pubEndDate"] = fim.strftime(formato)

    try:
        resposta = requests.get(URL, params=parametros, timeout=10)
        resposta.raise_for_status()
        return resposta.json()
    except requests.exceptions.RequestException as erro:
        print(f"Erro ao buscar CVEs: {erro}")
        return None


def extrair_dados(vulnerabilidade):
    cve = vulnerabilidade.get("cve", {})

    descricao = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            descricao = d.get("value")
            break

    nota = None
    severidade = None
    metricas = cve.get("metrics", {})
    for versao in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lista = metricas.get(versao, [])
        if lista:
            dados_cvss = lista[0].get("cvssData", {})
            nota = dados_cvss.get("baseScore")
            severidade = dados_cvss.get("baseSeverity") or lista[0].get("baseSeverity")
            break

    return {
        "id": cve.get("id"),
        "descricao": descricao,
        "nota": nota,
        "severidade": severidade,
    }


def filtrar_por_nota(lista, minimo):
    resultado = []
    for cve in lista:
        if cve["nota"] is not None and cve["nota"] >= minimo:
            resultado.append(cve)
    return resultado


def ordenar_por_nota(lista):
    return sorted(
        lista,
        key=lambda cve: cve["nota"] if cve["nota"] is not None else 0,
        reverse=True,
    )


def salvar_csv(lista, nome_arquivo):
    colunas = ["id", "descricao", "nota", "severidade"]
    with open(nome_arquivo, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=colunas)
        escritor.writeheader()
        escritor.writerows(lista)


def salvar_json(lista, nome_arquivo):
    with open(nome_arquivo, "w", encoding="utf-8") as arquivo:
        json.dump(lista, arquivo, ensure_ascii=False, indent=2)


def enviar_aviso(mensagem):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("Token ou chat_id não encontrados no .env")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resposta = requests.post(
            url,
            data={"chat_id": chat_id, "text": mensagem},
            timeout=10,
        )
        resposta.raise_for_status()
        print("Aviso enviado no Telegram")
    except requests.exceptions.HTTPError as erro:
        print(f"Erro ao enviar aviso: HTTP {erro.response.status_code}")
        print(erro.response.text)
    except requests.exceptions.RequestException as erro:
        print(f"Erro ao enviar aviso: {type(erro).__name__}")
# NOVO (passo 5)
def montar_mensagem(lista, limite=10):
    if not lista:
        return "Monitor de CVEs: nenhum CVE encontrado hoje."

    mostrados = lista[:limite]
    linhas = [f"🚨 {len(lista)} CVEs encontrados (top {len(mostrados)}):\n"]
    for cve in mostrados:
        descricao = (cve["descricao"] or "")[:100]
        linhas.append(f'{cve["id"]} | nota {cve["nota"]}\n{descricao}\n')

    return "\n".join(linhas)[:4000]  # Telegram aceita no máximo 4096 caracteres


def main():
    QUANTIDADE = 50
    SEVERIDADE = "CRITICAL"
    DIAS = 30
    PALAVRA = None
    NOTA_MINIMA = 0

    dados = buscar_cves(QUANTIDADE, SEVERIDADE, DIAS, PALAVRA)
    if dados is None:
        return

    cves = []
    for vulnerabilidade in dados.get("vulnerabilities", []):
        cves.append(extrair_dados(vulnerabilidade))

    filtrados = filtrar_por_nota(cves, NOTA_MINIMA)
    filtrados = ordenar_por_nota(filtrados)

    print(f"{len(filtrados)} CVEs encontrados\n")
    for cve in filtrados:
        print(f'{cve["id"]} | nota {cve["nota"]} | {cve["severidade"]}')
        print(f'   {(cve["descricao"] or "")[:150]}\n')

    data_hoje = datetime.now().strftime("%Y-%m-%d")
    salvar_csv(filtrados, f"cves_{data_hoje}.csv")
    salvar_json(filtrados, f"cves_{data_hoje}.json")
    print(f"Arquivos salvos: cves_{data_hoje}.csv e cves_{data_hoje}.json")

    enviar_aviso(montar_mensagem(filtrados))


if __name__ == "__main__":
    main()